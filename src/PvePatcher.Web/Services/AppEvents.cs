namespace PvePatcher.Web.Services;

/// <summary>Barramento simples de eventos para atualizar a UI (Blazor Server).</summary>
public sealed class AppEvents
{
    public event Action? DataChanged;
    public event Action? LogChanged;

    public void RaiseData() => DataChanged?.Invoke();
    public void RaiseLog() => LogChanged?.Invoke();
}
