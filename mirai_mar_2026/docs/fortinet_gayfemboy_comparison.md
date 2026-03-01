# Fortinet Gayfemboy Comparison (Static)

Source campaign write-up:
- [Fortinet: Gayfemboy Mirai-based Botnet Campaign](https://www.fortinet.com/blog/threat-research/iot-malware-gayfemboy-mirai-based-botnet-campaign) (published Sep 18, 2024)

## Result For This Sample

- Assessment: **Mirai-lineage overlap only (not enough for same campaign)**.
- Evidence file: `reports/json/fortinet_gayfemboy_overlap.json`.

## What Overlaps

- Resolver decoding byte motif used by Elastic Gafgyt rule `d0c57a2e` is present once.
- Mirai-like behavior markers are present:
  - `watchdogd`
  - `/proc/%s/exe`, `/proc/%s/cmdline`, `/proc/%s/maps`
  - `!SIGKILL`
  - SSDP/SIP payload templates (`M-SEARCH`, `Via: SIP/2.0/...`)

## What Does Not Overlap

- No direct campaign IOC strings from Fortinet figures:
  - domains such as `cross-compiling.org`, `i-kiss-boys.com`, `furry-femboys.top`, `twinkfinder.nl`, `3gipcam.com`
  - process killer keywords (`twinks :3`, `meowmeow`, `whattheflip`, `^kill^`)
  - watchdog UDP control port marker `47272`
  - anti-sandbox path markers (`/tmp/.`, `/bot.`, `/.ai`)

## Blog/Post Guidance

- Safe claim: shared **Mirai resolver + botnet tradecraft lineage**.
- Avoid overclaiming the exact Gayfemboy campaign without:
  - matching infrastructure/IOC overlap,
  - runtime beacon equivalence,
  - compatible process-killer/watchdog feature set.

