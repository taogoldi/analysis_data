# Family Comparison Notes (Kaiji / Ares-Like)

This section records what aligns with public reporting and what still needs runtime validation.

## Matches to Kaiji/Ares-style reporting
- Go ELF on Linux amd64.
- Ares module naming (`Ares_Tcp`, `Ares_L3_Udp`, `Ares_ipspoof`) preserved in symbol strings.
- Persistence indicators through service + cron style artifacts.
- Dedicated support routines (`Killcpu`, `Watchdog`) commonly seen in destructive or control-focused bot tooling.

## Current confidence boundaries
- Static evidence strongly supports Kaiji-like classification.
- C2 token decode (`air.xem.lat:25194|(odk)/*-`) is concrete.
- External IOC (`air.duffy.baby:888`) is retained as context but not directly recovered from this sample during this run.
- No live traffic replay or command execution performed.
