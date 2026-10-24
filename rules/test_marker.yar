/*
  Harmless test signature. `workshopguard selftest` (and `scan-item --inject-test`) plants a file containing this
  marker so you can see a detection and an alert end to end without any real malware.
*/

rule WorkshopGuard_Test_Marker
{
    meta:
        severity = "critical"
        description = "WorkshopGuard TEST marker: a planted fake detection, not real malware"
    strings:
        $m = "WORKSHOPGUARD-FAKE-MALWARE-TEST-7f3a91" ascii wide
    condition:
        $m
}
