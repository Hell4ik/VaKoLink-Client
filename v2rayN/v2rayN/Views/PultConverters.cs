namespace v2rayN.Views;

public sealed class PultNodeLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var label = (value as string)?.Trim() ?? "";
        var split = label.IndexOf(' ');
        var prefix = split > 0 ? label[..split] : "";
        var code = prefix.Normalize(NormalizationForm.FormKC).ToUpperInvariant();
        var flag = prefix.EnumerateRunes().Select(rune => rune.Value - 0x1F1E6).ToArray();
        if (flag.Length == 2 && flag.All(letter => letter is >= 0 and < 26))
        {
            code = string.Concat((char)('A' + flag[0]), (char)('A' + flag[1]));
        }
        if (!IsCountryCode(code))
        {
            return parameter is "Badge" ? "•" : label.Length > 0 ? label : "Нода не выбрана";
        }
        return parameter is "Badge" ? code : label[(split + 1)..].TrimStart();
    }

    private static bool IsCountryCode(string code)
    {
        if (code == "UK")
        {
            return true;
        }
        if (code.Length != 2 || !code.All(char.IsAsciiLetterUpper))
        {
            return false;
        }
        try
        {
            return new RegionInfo(code).TwoLetterISORegionName == code;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

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
