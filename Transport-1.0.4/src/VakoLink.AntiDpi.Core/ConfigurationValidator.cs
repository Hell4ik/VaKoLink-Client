namespace VakoLink.AntiDpi.Core;

public static class ConfigurationValidator
{
    public const int MaximumProfiles = 8;
    public static TimeSpan MaximumDuration { get; } = TimeSpan.FromMinutes(20);

    /// <summary>Validates exact executable path bindings; a port range is not an application identity.</summary>
    public static IReadOnlyList<string> Validate(
        IReadOnlyList<AppProfile> profiles,
        IReadOnlyList<ScenarioDefinition> scenarios,
        TimeSpan maximumDuration)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(scenarios);
        var errors = new List<string>();
        if (profiles.Count is < 1 or > MaximumProfiles)
        {
            errors.Add("Profile count must be between 1 and 8.");
        }

        if (maximumDuration <= TimeSpan.Zero || maximumDuration > MaximumDuration)
        {
            errors.Add("Run duration must be positive and at most 20 minutes.");
        }

        var profileIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var executablePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in profiles)
        {
            if (!ValidId(profile.Id) || !profileIds.Add(profile.Id))
            {
                errors.Add("Profile identifiers must be valid and unique.");
            }

            if (string.IsNullOrWhiteSpace(profile.DisplayName) || profile.DisplayName.Length > 120)
            {
                errors.Add("Profile display name must contain 1 to 120 characters.");
            }

            if (!TryNormalizeExecutable(profile.ExecutablePath, out var normalized)
                || !executablePaths.Add(normalized))
            {
                errors.Add("Executable bindings must be unique absolute .exe file paths.");
            }

            if (!StrategyCatalog.All.Any(strategy => string.Equals(strategy.Id, profile.StrategyId, StringComparison.Ordinal)))
            {
                errors.Add("Profile refers to an unknown strategy.");
            }
        }

        var scenarioIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var scenario in scenarios)
        {
            if (!ValidId(scenario.Id) || !scenarioIds.Add(scenario.Id))
            {
                errors.Add("Scenario identifiers must be valid and unique.");
            }

            if (string.IsNullOrWhiteSpace(scenario.DisplayName) || scenario.DisplayName.Length > 120)
            {
                errors.Add("Scenario display name must contain 1 to 120 characters.");
            }

            if (scenario.ProfileIds is null || scenario.ProfileIds.Count is < 1 or > MaximumProfiles)
            {
                errors.Add("A scenario must select between 1 and 8 profiles.");
                continue;
            }

            var selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var id in scenario.ProfileIds)
            {
                if (string.IsNullOrWhiteSpace(id) || !profileIds.Contains(id) || !selected.Add(id))
                {
                    errors.Add("Scenario profile references must exist and be unique.");
                }
            }
        }

        return errors.AsReadOnly();
    }

    private static bool ValidId(string? id) => id is { Length: >= 1 and <= 64 }
        && id.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool TryNormalizeExecutable(string? path, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            if (!Path.IsPathFullyQualified(path)
                || !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            normalized = Path.GetFullPath(path);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}
