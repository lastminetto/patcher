using Microsoft.AspNetCore.Components;

namespace PvePatcher.Web.Components.Shared;

/// <summary>Componente que se atualiza quando o estado da aplicação muda (com throttle de ~400 ms).</summary>
public abstract class LiveComponentBase : ComponentBase, IDisposable
{
    [Inject] protected AppEvents Events { get; set; } = default!;
    [Inject] protected TimeProvider Time { get; set; } = default!;

    private bool _disposed;
    private int _scheduled;

    protected virtual bool ListenToLogs => false;

    /// <summary>Recarrega os dados antes do novo render.</summary>
    protected virtual Task OnLiveRefreshAsync() => Task.CompletedTask;

    protected override void OnInitialized()
    {
        Events.DataChanged += OnEvent;
        if (ListenToLogs) Events.LogChanged += OnEvent;
    }

    private void OnEvent()
    {
        if (_disposed || Interlocked.Exchange(ref _scheduled, 1) == 1) return;
        _ = Task.Delay(400).ContinueWith(async _ =>
        {
            Interlocked.Exchange(ref _scheduled, 0);
            if (_disposed) return;
            try
            {
                await InvokeAsync(async () =>
                {
                    if (_disposed) return;
                    await OnLiveRefreshAsync();
                    StateHasChanged();
                });
            }
            catch (Exception) { /* circuito encerrado */ }
        });
    }

    public virtual void Dispose()
    {
        _disposed = true;
        Events.DataChanged -= OnEvent;
        Events.LogChanged -= OnEvent;
    }
}
