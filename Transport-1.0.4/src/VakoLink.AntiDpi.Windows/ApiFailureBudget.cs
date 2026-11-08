namespace VakoLink.AntiDpi.Windows;

public sealed class ApiFailureBudget
{
    public int Total { get; private set; }
    public int Consecutive { get; private set; }
    public bool MustStop => Consecutive >= 8;
    public void Success() => Consecutive = 0;
    public void Failure() { Total++; Consecutive++; }
}
