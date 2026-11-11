using System.Globalization;

namespace ServiceLib.Models.Dto;

public sealed record VaKoLinkConfigurationUsage(long? ExpiresAt, long? UsedBytes, long? TotalBytes)
{
    internal static VaKoLinkConfigurationUsage Parse(IEnumerable<string> headerValues)
    {
        var fields = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in headerValues.SelectMany(value => value.Split(';', StringSplitOptions.TrimEntries)))
        {
            var pair = field.Split('=', 2, StringSplitOptions.TrimEntries);
            if (pair.Length == 2 && long.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var number))
            {
                fields.TryAdd(pair[0], number);
            }
        }

        var expiresAt = fields.TryGetValue("expire", out var expires) && expires <= 253402300799
            ? (long?)expires : null;
        // The portal reports the full configuration usage in download.
        var usedBytes = fields.TryGetValue("download", out var download) ? (long?)download : null;
        return new(expiresAt, usedBytes, fields.TryGetValue("total", out var total) ? total : null);
    }
}
