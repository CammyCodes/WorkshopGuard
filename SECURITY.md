# Security

WorkshopGuard is a security tool, so two kinds of report matter most: malware it missed, and mods it flagged that
are actually fine. Both are welcome, and both get fixed in the rules with a test so they stay fixed.

## Malware it missed

Please report privately: on GitHub, open the **Security** tab and choose **Report a vulnerability**. Include:

- the game and the Workshop item ID (or the mod's name if it's from somewhere else),
- the SHA-256 of the file you think is malicious,
- what it does, if you know (stole a Steam login, posted to a Discord webhook, downloaded something...).

**Never attach the malware itself, or a working copy of it, to an issue or a discussion.** A hash is enough to find it
on MalwareBazaar or VirusTotal. If you've already uploaded it there, link it.

If the item is still live on the Workshop, report it to Valve as well (the item's page > Report), and to the game's
developers. WorkshopGuard can't take anything down for you.

## A mod flagged by mistake

Open a [False alarm](https://github.com/CammyCodes/WorkshopGuard/issues/new?template=false_alarm.yml) issue. If
you're the mod's author and would rather not discuss your code in public, use the private report above instead.

A false alarm is treated as a bug in WorkshopGuard, not a mark against the mod. The verdict wording is careful on
purpose ("suspicious" means a person should look), and please don't post a flagged mod as malware anywhere until a
known-malware engine agrees or a person has read its code.

## A bug in WorkshopGuard itself

Something that lets a mod get past the launch gate, run code during a scan, escape the scanner's container, or that
leaks a Steam login, publisher key or webhook URL: report it privately as above. Anything else is a normal
[issue](https://github.com/CammyCodes/WorkshopGuard/issues).

## What to expect

You'll get a reply within a week, usually sooner. Fixes go into the latest release only. The Docker image rebuilds
every week with fresh community rules, so pull `latest` (or the newest version tag) to stay current.

Credit is given in the changelog unless you'd rather stay anonymous.
