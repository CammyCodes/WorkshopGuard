// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Runtime.InteropServices;

namespace WorkshopGuard
{
    /// <summary>The player's own antivirus, through Windows' Antimalware Scan Interface (AMSI): the same API Windows
    /// uses to scan scripts before they run. Microsoft Defender (and most other antivirus products) answer it. Each
    /// new mod file's bytes are handed over before the game loads them. Missing on Linux/Proton or old Windows: then
    /// <see cref="Available"/> is false and ModGuard carries on with its own checks.</summary>
    public sealed class WindowsAntivirus : IDisposable
    {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiInitialize(string appName, out IntPtr context);
        [DllImport("amsi.dll")]
        static extern void AmsiUninitialize(IntPtr context);
        [DllImport("amsi.dll")]
        static extern int AmsiOpenSession(IntPtr context, out IntPtr session);
        [DllImport("amsi.dll")]
        static extern void AmsiCloseSession(IntPtr context, IntPtr session);
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

        const int AmsiResultDetected = 32768;
        IntPtr context = IntPtr.Zero, session = IntPtr.Zero;

        public bool Available { get; private set; }
        public string Problem { get; private set; }

        public WindowsAntivirus(string appName)
        {
            try
            {
                if (Environment.OSVersion.Platform != PlatformID.Win32NT) { Problem = "not Windows"; return; }
                int hr = AmsiInitialize(appName, out context);
                if (hr != 0) { Problem = "AmsiInitialize failed (0x" + hr.ToString("x8") + ")"; return; }
                hr = AmsiOpenSession(context, out session);
                if (hr != 0) { Problem = "AmsiOpenSession failed (0x" + hr.ToString("x8") + ")"; return; }
                Available = true;
                // AMSI can be present with nothing behind it (antivirus off, or one that doesn't support AMSI):
                // then every scan fails, so say so now rather than leave every file "not fully checked"
                if (Scan(System.Text.Encoding.UTF8.GetBytes("WorkshopGuard ModGuard probe"), "probe") == Result.Error)
                {
                    Available = false;
                    Problem = "no antivirus is answering Windows AMSI";
                }
            }
            catch (DllNotFoundException) { Problem = "amsi.dll isn't available (Windows 10+ only)"; }
            catch (EntryPointNotFoundException) { Problem = "amsi.dll is too old"; }
        }

        public enum Result { Clean, Detected, BlockedByAdmin, Error }

        /// <summary>Hands one file's bytes to the antivirus. <paramref name="name"/> shows up in its logs.</summary>
        public Result Scan(byte[] data, string name)
        {
            if (!Available || data.Length == 0) return Result.Error;
            int result;
            try
            {
                int hr = AmsiScanBuffer(context, data, (uint)data.Length, name, session, out result);
                if (hr != 0) return Result.Error;
            }
            catch (Exception) { return Result.Error; }
            if (result >= AmsiResultDetected) return Result.Detected;
            if (result >= 0x4000 && result <= 0x4FFF) return Result.BlockedByAdmin;
            return Result.Clean;
        }

        public void Dispose()
        {
            try
            {
                if (session != IntPtr.Zero) AmsiCloseSession(context, session);
                if (context != IntPtr.Zero) AmsiUninitialize(context);
            }
            catch (Exception) { }
            session = context = IntPtr.Zero;
            Available = false;
        }
    }
}
