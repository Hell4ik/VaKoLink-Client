using System.Text.Json;
using System.Windows.Media.Imaging;

namespace v2rayN.Views;

public sealed class PultActiveNodeConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
        values[0] is string nodeId && values[1] is string activeId && nodeId == activeId;

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class PultNodeLabelConverter : IValueConverter
{
    private const string FlagsRoot = "pack://application:,,,/VaKoLink;component/Resources/Flags/";
    private static readonly Lazy<Dictionary<string, string[]>> Countries = new(() =>
    {
        using var stream = Application.GetResourceStream(new Uri(FlagsRoot + "countries.json")).Stream;
        return JsonSerializer.Deserialize<Dictionary<string, string[]>>(stream)!;
    });
    private static readonly Lazy<(string Code, string Name)[]> CountryNames = new(() => Countries.Value
        .SelectMany(country => country.Value.Select(name => (Code: country.Key, Name: name)))
        .OrderByDescending(country => country.Name.Length).ToArray());
    private static readonly Dictionary<string, BitmapSource> Flags = new(StringComparer.Ordinal);

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var label = (value as string)?.Trim() ?? "";
        var (code, prefixLength) = ReadPrefix(label);
        if (parameter is "Flag")
        {
            code ??= CountryNames.Value.FirstOrDefault(country => label.StartsWith(country.Name, StringComparison.OrdinalIgnoreCase)
                && (label.Length == country.Name.Length || IsSeparator(label[country.Name.Length]))).Code;
            if (code is null)
            {
                return null!;
            }
            if (!Flags.TryGetValue(code, out var flag))
            {
                flag = BitmapFrame.Create(new Uri(FlagsRoot + code + ".png"), BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
                flag.Freeze();
                Flags.Add(code, flag);
            }
            return flag;
        }
        var name = label[prefixLength..].TrimStart(' ', '·', '-', '–', '—');
        return name.Length > 0 ? name : label.Length > 0 ? label : "Нода не выбрана";
    }

    private static (string? Code, int Length) ReadPrefix(string label)
    {
        var flag = label.EnumerateRunes().Take(2).Select(rune => rune.Value - 0x1F1E6).ToArray();
        if (flag is [var first, var second] && first is >= 0 and < 26 && second is >= 0 and < 26)
        {
            var emojiCode = string.Concat((char)('a' + first), (char)('a' + second));
            return Countries.Value.ContainsKey(emojiCode) ? (emojiCode, 4) : (null, 0);
        }
        if (label.Length > 2 && IsSeparator(label[2]))
        {
            var code = label[..2].Normalize(NormalizationForm.FormKC).ToLowerInvariant();
            code = code == "uk" ? "gb" : code;
            if (Countries.Value.ContainsKey(code))
            {
                return (code, 2);
            }
        }
        return (null, 0);
    }

    private static bool IsSeparator(char value) => char.IsWhiteSpace(value) || value is '·' or '-' or '–' or '—' or ',' or ':';

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class PultDelayConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (string.IsNullOrWhiteSpace(value as string))
        {
            return parameter is "Band" ? "" : "—";
        }
        if (!int.TryParse((string)value, out var delay) || delay < 0)
        {
            return parameter is "Band" ? "" : "Нет ответа";
        }
        return parameter is "Band"
            ? delay <= 100 ? "Good" : delay <= 250 ? "Medium" : "Bad"
            : $"{delay} мс";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
