using System.Diagnostics;
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using PvePatcher.Core;
using PvePatcher.Web.Auth;

namespace PvePatcher.Web.Services;

/// <summary>
/// Endpoints do terminal: WebSocket do shell (fora do circuito do Blazor) e download/upload do SFTP.
/// Exigem login ("View") e, nos que mudam estado, Origin igual ao host (anti CSWSH/CSRF).
/// </summary>
public static class TerminalEndpoints
{
    public static void MapTerminal(this WebApplication app)
    {
        var g = app.MapGroup("/terminal").RequireAuthorization("View");
        // Map, não MapGet: sobre HTTP/2 (HTTPS do Kestrel) o navegador abre o WebSocket com CONNECT, não GET.
        g.Map("/ws", ShellAsync);
        g.MapGet("/sftp/download", DownloadAsync);
        g.MapPost("/sftp/upload", UploadAsync).DisableAntiforgery();
    }

    private static bool SameOrigin(HttpContext ctx)
    {
        if (TerminalProtocol.IsSameOrigin(ctx.Request.Headers.Origin, ctx.Request.Scheme, ctx.Request.Host.Value ?? "")) return true;
        // Atrás de proxy, um Host/X-Forwarded-Host reescrito cai aqui: o log mostra os dois lados.
        ctx.RequestServices.GetRequiredService<ILogger<ConsoleService>>().LogWarning(
            "Terminal: recusado por Origin {Origin} diferente de {Scheme}://{Host} ({Path})",
            ctx.Request.Headers.Origin.ToString(), ctx.Request.Scheme, ctx.Request.Host.Value, ctx.Request.Path);
        return false;
    }

    private static string AppUser(HttpContext ctx) => UserInfo.FromPrincipal(ctx.User)?.UserId ?? ctx.User.Identity?.Name ?? "?";

    // --- shell ---------------------------------------------------------------

    private static async Task ShellAsync(HttpContext ctx, ConsoleService console, ConsoleSessionRegistry registry)
    {
        if (!ctx.WebSockets.IsWebSocketRequest)
        {
            ctx.RequestServices.GetRequiredService<ILogger<ConsoleService>>().LogWarning(
                "Terminal: {Method} {Protocol} em /terminal/ws sem upgrade de WebSocket (proxy sem suporte?)", ctx.Request.Method, ctx.Request.Protocol);
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (!SameOrigin(ctx)) { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return; }

        var q = ctx.Request.Query;
        var cols = int.TryParse(q["cols"], out var c) ? Math.Clamp(c, 1, TerminalProtocol.MaxDimension) : 80;
        var rows = int.TryParse(q["rows"], out var r) ? Math.Clamp(r, 1, TerminalProtocol.MaxDimension) : 24;
        using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
        var ct = ctx.RequestAborted;
        var user = AppUser(ctx);

        // Erros vão pelo próprio WebSocket: o navegador esconde o motivo de um handshake recusado.
        if (!TerminalProtocol.TryParseVm(q["vm"], out var key)) { await FailAsync(ws, "VM inválida.", ct); return; }
        using var lease = registry.TryAcquire(user, out var reason);
        if (lease is null) { await FailAsync(ws, reason!, ct); return; }

        IShellSession shell;
        try { (shell, _) = await console.OpenShellAsync(user, key, cols, rows, ct); }
        catch (JobFailedException ex) { await FailAsync(ws, ex.Message, ct); return; }

        var started = Stopwatch.GetTimestamp();
        long bytesIn = 0, bytesOut = 0;
        string? endReason = null;
        await using (shell)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var toBrowser = Task.Run(async () =>
            {
                var buf = new byte[16 * 1024];
                try
                {
                    while (true)
                    {
                        var n = await shell.ReadAsync(buf, cts.Token);
                        if (n == 0) break;
                        Interlocked.Add(ref bytesOut, n);
                        await ws.SendAsync(buf.AsMemory(0, n), WebSocketMessageType.Binary, true, cts.Token);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { endReason ??= ex.Message; }
            });
            // A recepção usa só o token da requisição: cancelar um ReceiveAsync aborta o WebSocket (sem close limpo).
            var fromBrowser = Task.Run(async () =>
            {
                var buf = new byte[16 * 1024];
                var text = new MemoryStream();
                try
                {
                    while (ws.State == WebSocketState.Open)
                    {
                        var res = await ws.ReceiveAsync(buf.AsMemory(), ct);
                        if (res.MessageType == WebSocketMessageType.Close) break;
                        if (res.MessageType == WebSocketMessageType.Binary)
                        {
                            Interlocked.Add(ref bytesIn, res.Count);
                            await shell.WriteAsync(buf.AsMemory(0, res.Count), cts.Token);
                            continue;
                        }
                        if (text.Length + res.Count > 4096) { text.SetLength(0); continue; } // controle é pequeno
                        text.Write(buf, 0, res.Count);
                        if (!res.EndOfMessage) continue;
                        var msg = Encoding.UTF8.GetString(text.GetBuffer(), 0, (int)text.Length);
                        text.SetLength(0);
                        if (TerminalProtocol.TryParseResize(msg, out var nc, out var nr)) shell.Resize(nc, nr);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { endReason ??= ex.Message; }
            });

            var first = await Task.WhenAny(toBrowser, fromBrowser);
            if (first == toBrowser && ws.State == WebSocketState.Open)
            {
                // O shell acabou (exit, conexão caiu): avisa e fecha; a recepção termina quando o navegador confirmar.
                try
                {
                    await ws.SendAsync(Encoding.UTF8.GetBytes(TerminalProtocol.Closed), WebSocketMessageType.Text, true, CancellationToken.None);
                    await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "fim", CancellationToken.None);
                }
                catch { /* navegador já foi */ }
                if (await Task.WhenAny(fromBrowser, Task.Delay(TimeSpan.FromSeconds(3), CancellationToken.None)) != fromBrowser) ws.Abort();
            }
            else if (ws.State == WebSocketState.CloseReceived)
            {
                try { await ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "fim", CancellationToken.None); } catch { }
            }
            await cts.CancelAsync();
            if (!fromBrowser.IsCompleted) ws.Abort(); // destrava a recepção que ficou pendurada
            await shell.DisposeAsync(); // destrava a leitura do shell
            try { await Task.WhenAll(toBrowser, fromBrowser); } catch { /* já registrado */ }
        }

        console.LogClosed(user, key, Stopwatch.GetElapsedTime(started), bytesIn, bytesOut, endReason);
    }

    private static async Task FailAsync(WebSocket ws, string message, CancellationToken ct)
    {
        try
        {
            await ws.SendAsync(Encoding.UTF8.GetBytes(TerminalProtocol.Error(message)), WebSocketMessageType.Text, true, ct);
            await ws.CloseAsync(WebSocketCloseStatus.PolicyViolation, "erro", ct);
        }
        catch { /* navegador já foi */ }
    }

    // --- SFTP ----------------------------------------------------------------

    private static async Task<IResult> DownloadAsync(HttpContext ctx, ConsoleService console, string vm, string path)
    {
        if (!TerminalProtocol.TryParseVm(vm, out var key)) return Results.BadRequest("VM inválida.");
        var user = AppUser(ctx);
        try
        {
            await console.WithSftpAsync(user, key, $"download {path}", async sftp =>
            {
                var entry = await sftp.StatAsync(path, ctx.RequestAborted);
                if (entry.IsDirectory) throw new JobFailedException("É um diretório.");
                ctx.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();
                ctx.Response.ContentType = "application/octet-stream";
                ctx.Response.ContentLength = entry.Size;
                var cd = new ContentDispositionHeaderValue("attachment");
                cd.SetHttpFileName(entry.Name);
                ctx.Response.Headers.ContentDisposition = cd.ToString();
                await sftp.DownloadAsync(path, ctx.Response.Body, ctx.RequestAborted);
            }, ctx.RequestAborted);
            return Results.Empty; // o corpo já foi enviado em streaming
        }
        catch (JobFailedException ex) when (!ctx.Response.HasStarted)
        {
            return Results.Text(ex.Message, "text/plain; charset=utf-8", statusCode: StatusCodes.Status400BadRequest);
        }
    }

    private static async Task<IResult> UploadAsync(HttpContext ctx, ConsoleService console, IOptions<ConsoleOptions> options, string vm, string dir, bool? overwrite)
    {
        if (!SameOrigin(ctx)) return Results.StatusCode(StatusCodes.Status403Forbidden);
        if (!TerminalProtocol.TryParseVm(vm, out var key)) return Results.BadRequest("VM inválida.");
        var boundary = HeaderUtilities.RemoveQuotes(MediaTypeHeaderValue.Parse(ctx.Request.ContentType ?? "").Boundary).Value;
        if (string.IsNullOrEmpty(boundary)) return Results.BadRequest("Esperado multipart/form-data.");
        if (ctx.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } size)
            size.MaxRequestBodySize = (long)options.Value.MaxUploadMegabytes * 1024 * 1024;

        var user = AppUser(ctx);
        var names = new List<string>();
        try
        {
            await console.WithSftpAsync(user, key, "", async sftp =>
            {
                var reader = new MultipartReader(boundary, ctx.Request.Body);
                while (await reader.ReadNextSectionAsync(ctx.RequestAborted) is { } section)
                {
                    if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var cd) || !cd.IsFileDisposition()) continue;
                    var name = Path.GetFileName((cd.FileNameStar.HasValue ? cd.FileNameStar : cd.FileName).Value?.Trim('"') ?? "");
                    var target = SftpPaths.Combine(dir, name); // valida o nome
                    await sftp.UploadAsync(section.Body, target, overwrite == true, ctx.RequestAborted);
                    names.Add(name);
                }
            }, ctx.RequestAborted);
        }
        catch (ArgumentException ex) { return Results.Text(ex.Message, "text/plain; charset=utf-8", statusCode: 400); }
        catch (JobFailedException ex) { return Results.Text(ex.Message, "text/plain; charset=utf-8", statusCode: 400); }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return Results.Text($"Arquivo maior que o limite de {options.Value.MaxUploadMegabytes} MB.", "text/plain; charset=utf-8", statusCode: 413);
        }
        ctx.RequestServices.GetRequiredService<ILogger<ConsoleService>>()
            .LogInformation("SFTP: {AppUser} em {Vm}: upload {Files} para {Dir}", user, key, string.Join(", ", names), dir);
        return Results.Ok(new { files = names });
    }
}
