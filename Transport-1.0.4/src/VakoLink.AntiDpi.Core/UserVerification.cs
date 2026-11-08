namespace VakoLink.AntiDpi.Core;

public enum UserConfirmedOutcome
{
    NotTested,
    Failed,
    ConfirmedWorking,
}

/// <summary>
/// An explicitly entered user result, independent of packet counters or engine startup.
/// Strategy selection is keyed by profile; the scenario result requires both match and voice.
/// </summary>
public sealed record UserVerification(
    string ScenarioId,
    IReadOnlyDictionary<string, string> ProfileStrategies,
    UserConfirmedOutcome Match,
    UserConfirmedOutcome BidirectionalVoice,
    bool ExplicitlyConfirmed,
    DateTimeOffset ConfirmedAt)
{
    public bool CombinedSuccess => ExplicitlyConfirmed
        && Match == UserConfirmedOutcome.ConfirmedWorking
        && BidirectionalVoice == UserConfirmedOutcome.ConfirmedWorking;
}

/// <summary>In-memory policy gate; persistence is an application responsibility.</summary>
public sealed class VerificationStore
{
    private readonly List<UserVerification> verified = [];

    public IReadOnlyList<UserVerification> Verified => verified.AsReadOnly();

    public bool SaveConfirmed(UserVerification verification)
    {
        ArgumentNullException.ThrowIfNull(verification);
        if (!verification.CombinedSuccess || string.IsNullOrWhiteSpace(verification.ScenarioId)
            || verification.ProfileStrategies.Count == 0
            || verification.ProfileStrategies.Any(pair => string.IsNullOrWhiteSpace(pair.Key)
                || !StrategyCatalog.All.Any(strategy => string.Equals(strategy.Id, pair.Value, StringComparison.Ordinal))))
        {
            return false;
        }

        // Freeze the mapping: changing the editor afterwards cannot change a previously confirmed result.
        var mapping = new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(verification.ProfileStrategies, StringComparer.Ordinal));
        verified.Add(verification with { ProfileStrategies = mapping });
        return true;
    }
}
