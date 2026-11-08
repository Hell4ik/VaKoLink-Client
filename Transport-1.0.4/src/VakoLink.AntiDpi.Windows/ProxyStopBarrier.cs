namespace VakoLink.AntiDpi.Windows;

public static class ProxyStopBarrier
{
    // A failed diagnostic task must never prevent stopping the owned core. A still-running task prevents a clean claim.
    public static async Task<string> DrainAsync(Task? task, int milliseconds)
    {
        if (milliseconds is < 1 or > 20000) throw new ArgumentOutOfRangeException(nameof(milliseconds));
        if (task is null) return "NotStarted";
        try { await task.WaitAsync(TimeSpan.FromMilliseconds(milliseconds)); return "Completed"; }
        catch (TimeoutException) { return "Timeout_CoreStopMustContinue"; }
        catch { return "FinishedWithError_CoreStopMustContinue"; }
    }
}
