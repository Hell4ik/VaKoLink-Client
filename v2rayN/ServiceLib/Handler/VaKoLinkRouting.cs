namespace ServiceLib.Handler;

internal static class VaKoLinkRouting
{
    public static RoutingItem ForMode(bool useTun)
    {
        var id = useTun ? "vakolink-games-tun" : "vakolink-surfing-proxy";
        var name = useTun ? "Global + TUN" : "Surfing + Proxy";
        var file = useTun ? "games-tun.json" : "surfing-proxy.json";
        var ruleSet = EmbedUtils.GetEmbedText($"ServiceLib.Sample.VaKoLink.{file}");
        var rules = ReadRules(ruleSet);
        if (rules is null || !rules.Any(rule =>
                rule.Enabled && rule.RuleType != ERuleType.DNS && !string.IsNullOrWhiteSpace(rule.OutboundTag)))
        {
            throw new InvalidDataException($"В сборке отсутствуют правила VaKoLink «{name}».");
        }
        return new RoutingItem
        {
            Id = id,
            Remarks = name,
            Url = string.Empty,
            RuleSet = ruleSet,
            RuleNum = rules.Count,
            DomainStrategy = "IPIfNonMatch"
        };
    }

    public static async Task EnsureInstalledAsync()
    {
        var existing = await AppManager.Instance.RoutingItems() ?? [];
        var proxy = ForMode(false);
        await UpgradeRockstarRuleAsync(existing, proxy);
        var names = existing.Select(item => item.Remarks).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var sort = existing.Count > 0 ? existing.Max(item => item.Sort) : 0;
        foreach (var preset in new[] { proxy, ForMode(true) })
        {
            if (existing.Any(item => item.Id == preset.Id || MatchesImportedPreset(item, preset)))
            {
                continue;
            }

            var label = preset.Remarks;
            var suffix = 1;
            while (!names.Add(preset.Remarks))
            {
                preset.Remarks = suffix == 1 ? $"{label} (VaKoLink)" : $"{label} (VaKoLink {suffix})";
                suffix++;
            }
            preset.Sort = ++sort;
            await SQLiteHelper.Instance.InsertIfMissingAsync(preset);
        }
    }

    private static async Task UpgradeRockstarRuleAsync(List<RoutingItem> existing, RoutingItem proxy)
    {
        // Before v1.32 the built-in Proxy rules had no leading Rockstar exception.
        var rules = ReadRules(proxy.RuleSet)!;
        var previousPreset = new RoutingItem
        {
            Remarks = proxy.Remarks,
            DomainStrategy = proxy.DomainStrategy,
            RuleSet = JsonUtils.Serialize(rules.Skip(1).ToList(), false)
        };
        foreach (var item in existing.Where(item => MatchesImportedPreset(item, previousPreset)))
        {
            item.RuleSet = proxy.RuleSet;
            item.RuleNum = proxy.RuleNum;
            await SQLiteHelper.Instance.UpdateAsync(item);
        }
    }

    internal static bool MatchesImportedPreset(RoutingItem item, RoutingItem preset)
    {
        if (!item.Enabled || !string.Equals(item.DomainStrategy, preset.DomainStrategy, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(item.DomainStrategy4Singbox) || !string.IsNullOrEmpty(item.CustomRulesetPath4Singbox))
        {
            return false;
        }

        var name = item.Remarks ?? string.Empty;
        if (name.StartsWith("VaKoLink-", StringComparison.OrdinalIgnoreCase))
        {
            name = name["VaKoLink-".Length..];
        }
        if (!name.Equals(preset.Remarks, StringComparison.OrdinalIgnoreCase) &&
            !name.StartsWith(preset.Remarks + " (", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (item.RuleSet == preset.RuleSet)
        {
            return true;
        }
        var rules = ReadRules(item.RuleSet);
        return rules is not null &&
            JsonUtils.Serialize(rules, false) == JsonUtils.Serialize(ReadRules(preset.RuleSet), false);
    }

    private static List<RulesItem>? ReadRules(string? ruleSet)
    {
        var rules = JsonUtils.Deserialize<List<RulesItem>>(ruleSet);
        if (rules is null || rules.Any(rule => rule is null))
        {
            return null;
        }
        foreach (var rule in rules)
        {
            // The v2rayN importer assigns fresh IDs. They do not affect rule behavior.
            rule.Id = string.Empty;
        }
        return rules;
    }
}
