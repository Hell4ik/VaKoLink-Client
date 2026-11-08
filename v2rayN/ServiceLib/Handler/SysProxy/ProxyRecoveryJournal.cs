namespace ServiceLib.Handler.SysProxy;

[Flags]
internal enum ProxyOptionFields
{
    None = 0,
    Flags = 1,
    Server = 2,
    Bypass = 4
}

internal sealed record ProxyOptions(int Flags, string? Server, string? Bypass);

internal sealed class ProxyRecoveryJournal(
    string path,
    Func<IEnumerable<string?>> connections,
    Func<string?, ProxyOptions> read,
    Action<string?, ProxyOptions, ProxyOptionFields> write)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };

    private FileStream? _lease;

    internal ProxyOptions Enable(int flags, string server, string bypass)
    {
        var lease = AcquireLease();
        Change[] changes;
        try
        {
            if (ReadSnapshot() is not null)
            {
                throw new InvalidOperationException("Сначала восстановите сохранённые настройки прокси.");
            }
            changes = ConnectionNames().Select(name =>
            {
                var before = read(name);
                var planned = new ProxyOptions(flags, server, string.IsNullOrEmpty(bypass) ? before.Bypass : bypass);
                return new Change(name, before, planned);
            }).ToArray();
            SaveSnapshot(changes);
            _lease = lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }

        foreach (var change in changes)
        {
            var fields = DifferentFields(change.Before, change.Planned);
            if (fields == ProxyOptionFields.None)
            {
                continue;
            }
            if ((DifferentFields(change.Before, read(change.Name)) & fields) != ProxyOptionFields.None)
            {
                throw new InvalidOperationException("Настройки прокси изменились во время подключения.");
            }
            write(change.Name, change.Planned, fields);
            if ((DifferentFields(change.Planned, read(change.Name)) & fields) != ProxyOptionFields.None)
            {
                throw new InvalidOperationException("Windows не подтвердила включение системного прокси.");
            }
        }

        return changes[0].Planned;
    }

    internal void Recover()
    {
        using var lease = AcquireLease();
        RestoreSnapshot();
    }

    internal void Restore()
    {
        if (_lease is null)
        {
            return;
        }
        RestoreSnapshot();
        _lease.Dispose();
        _lease = null;
    }

    // A second instance sharing this data directory must not recover a live session.
    private FileStream AcquireLease() => new(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

    private string?[] ConnectionNames() =>
        new string?[] { null }.Concat(connections()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private Change[]? ReadSnapshot()
    {
        try
        {
            using var file = File.OpenRead(path);
            var changes = JsonSerializer.Deserialize<Change[]>(file, JsonOptions);
            if (changes is not { Length: > 0 } || changes.Any(change => change is null) ||
                changes[0].Name is not null ||
                changes.Select(change => change.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != changes.Length)
            {
                throw new InvalidDataException("Повреждён снимок настроек прокси.");
            }
            return changes;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private void SaveSnapshot(Change[] changes)
    {
        // Publish the complete snapshot in the same directory before writing any proxy options.
        var pendingPath = path + ".tmp";
        using (var file = new FileStream(pendingPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(file, changes, JsonOptions);
            file.Flush(flushToDisk: true);
        }
        File.Move(pendingPath, path);
    }

    private void RestoreSnapshot()
    {
        var changes = ReadSnapshot();
        if (changes is null)
        {
            return;
        }
        var names = ConnectionNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var errors = new List<Exception>();
        foreach (var change in changes.Reverse())
        {
            if (!names.Contains(change.Name))
            {
                continue;
            }
            try
            {
                var changed = DifferentFields(change.Before, change.Planned);
                var fields = changed & ~DifferentFields(change.Planned, read(change.Name));
                if (fields != ProxyOptionFields.None)
                {
                    write(change.Name, change.Before, fields);
                    if ((fields & ~DifferentFields(change.Planned, read(change.Name))) != ProxyOptionFields.None)
                    {
                        throw new IOException("Windows не подтвердила восстановление настроек прокси.");
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        }
        if (errors.Count > 0)
        {
            throw new AggregateException("Не удалось восстановить настройки прокси. Снимок сохранён.", errors);
        }
        File.Delete(path);
    }

    private static ProxyOptionFields DifferentFields(ProxyOptions left, ProxyOptions right)
    {
        var fields = ProxyOptionFields.None;
        if (left.Flags != right.Flags) fields |= ProxyOptionFields.Flags;
        if ((left.Server ?? "") != (right.Server ?? "")) fields |= ProxyOptionFields.Server;
        if ((left.Bypass ?? "") != (right.Bypass ?? "")) fields |= ProxyOptionFields.Bypass;
        return fields;
    }

    private sealed record Change(string? Name, ProxyOptions Before, ProxyOptions Planned);
}
