using static ServiceLib.Handler.SysProxy.ProxySettingWindows.InternetConnectionOption;

namespace ServiceLib.Handler.SysProxy;

public static partial class ProxySettingWindows
{
    public sealed class TemporaryProxy
    {
        private readonly ProxyRecoveryJournal _journal = CreateJournal();
        private ProxyOptions? _expected;

        public void Enable(Config config, int port)
        {
            var (server, bypass) = SysProxyHandler.GetWindowsProxyString(config, port);
            var flags = PerConnFlags.PROXY_TYPE_DIRECT | PerConnFlags.PROXY_TYPE_PROXY;
            _expected = _journal.Enable((int)flags, server, bypass);
        }

        public void Restore() => _journal.Restore();

        public static void RecoverOnStartup() => CreateJournal().Recover();

        public bool IsEnabled()
        {
            var current = Read(null);
            return _expected is not null && current.Flags == _expected.Flags &&
                string.Equals(current.Server, _expected.Server, StringComparison.OrdinalIgnoreCase);
        }

        private static ProxyRecoveryJournal CreateJournal() =>
            new(Utils.GetPath("vakolink-proxy-recovery.json"), EnumerateRasEntries, Read, Write);

        private static ProxyOptions Read(string? name)
        {
            var options = new InternetConnectionOption[]
            {
                new() { m_Option = PerConnOption.INTERNET_PER_CONN_FLAGS_UI },
                new() { m_Option = PerConnOption.INTERNET_PER_CONN_PROXY_SERVER },
                new() { m_Option = PerConnOption.INTERNET_PER_CONN_PROXY_BYPASS }
            };
            try
            {
                return Access(name, options, read: true)!;
            }
            catch (Win32Exception)
            {
                options[0].m_Option = PerConnOption.INTERNET_PER_CONN_FLAGS;
                return Access(name, options, read: true)!;
            }
        }

        private static void Write(string? name, ProxyOptions values, ProxyOptionFields fields)
        {
            var options = new List<InternetConnectionOption>();
            if (fields.HasFlag(ProxyOptionFields.Flags))
            {
                options.Add(new()
                {
                    m_Option = PerConnOption.INTERNET_PER_CONN_FLAGS,
                    m_Value = new() { m_Int = values.Flags }
                });
            }
            if (fields.HasFlag(ProxyOptionFields.Server))
            {
                options.Add(new()
                {
                    m_Option = PerConnOption.INTERNET_PER_CONN_PROXY_SERVER,
                    m_Value = new() { m_StringPtr = Marshal.StringToHGlobalAuto(values.Server ?? string.Empty) }
                });
            }
            if (fields.HasFlag(ProxyOptionFields.Bypass))
            {
                options.Add(new()
                {
                    m_Option = PerConnOption.INTERNET_PER_CONN_PROXY_BYPASS,
                    m_Value = new() { m_StringPtr = Marshal.StringToHGlobalAuto(values.Bypass ?? string.Empty) }
                });
            }
            Access(name, options.ToArray(), read: false);
            _ = NativeMethods.InternetSetOption(0, InternetOption.INTERNET_OPTION_SETTINGS_CHANGED, 0, 0);
            _ = NativeMethods.InternetSetOption(0, InternetOption.INTERNET_OPTION_REFRESH, 0, 0);
        }

        private static ProxyOptions? Access(string? name, InternetConnectionOption[] options, bool read)
        {
            var optionSize = Marshal.SizeOf<InternetConnectionOption>();
            var listSize = Marshal.SizeOf<InternetPerConnOptionList>();
            var arrayPtr = Marshal.AllocHGlobal(optionSize * options.Length);
            var listPtr = Marshal.AllocHGlobal(listSize);
            var namePtr = Marshal.StringToHGlobalAuto(name);
            try
            {
                for (var i = 0; i < options.Length; i++)
                {
                    Marshal.StructureToPtr(options[i], arrayPtr + i * optionSize, false);
                }
                Marshal.StructureToPtr(new InternetPerConnOptionList
                {
                    dwSize = listSize,
                    szConnection = namePtr,
                    dwOptionCount = options.Length,
                    options = arrayPtr
                }, listPtr, false);

                var success = read
                    ? InternetQueryOption(0, InternetOption.INTERNET_OPTION_PER_CONNECTION_OPTION, listPtr, ref listSize)
                    : NativeMethods.InternetSetOption(0, InternetOption.INTERNET_OPTION_PER_CONNECTION_OPTION, listPtr, listSize);
                if (!success)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                }
                return !read ? null : new(
                    Marshal.PtrToStructure<InternetConnectionOption>(arrayPtr).m_Value.m_Int,
                    Marshal.PtrToStringAuto(Marshal.PtrToStructure<InternetConnectionOption>(arrayPtr + optionSize).m_Value.m_StringPtr),
                    Marshal.PtrToStringAuto(Marshal.PtrToStructure<InternetConnectionOption>(arrayPtr + 2 * optionSize).m_Value.m_StringPtr));
            }
            finally
            {
                for (var i = 0; i < options.Length; i++)
                {
                    if (options[i].m_Option is not (PerConnOption.INTERNET_PER_CONN_PROXY_SERVER or
                        PerConnOption.INTERNET_PER_CONN_PROXY_BYPASS))
                    {
                        continue;
                    }
                    if (read)
                    {
                        var ptr = Marshal.PtrToStructure<InternetConnectionOption>(arrayPtr + i * optionSize).m_Value.m_StringPtr;
                        if (ptr != 0) _ = GlobalFree(ptr);
                    }
                    else
                    {
                        Marshal.FreeHGlobal(options[i].m_Value.m_StringPtr);
                    }
                }
                Marshal.FreeHGlobal(namePtr);
                Marshal.FreeHGlobal(arrayPtr);
                Marshal.FreeHGlobal(listPtr);
            }
        }

    }

    [DllImport("WinInet.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetQueryOption(nint internet, InternetOption option, nint buffer, ref int length);

    [DllImport("kernel32.dll")]
    private static extern nint GlobalFree(nint memory);
}
