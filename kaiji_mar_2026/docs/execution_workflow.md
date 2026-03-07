# Execution Workflow Notes

This static reconstruction is based on string artifacts, Go symbol remnants, and decoded embedded tokens.

1. `linux_amd64` starts as a statically linked Go ELF.
2. Persistence artifacts suggest service + cron installation (`quotaoff.service`, `/etc/crontab`).
3. Embedded Base64 token decodes to `air.xem.lat:25194|(odk)/*-`.
4. Ares-style modules (`Ares_Tcp`, `Ares_L3_Udp`, `Ares_ipspoof`) indicate attack dispatch capability.
5. `Killcpu` and watchdog paths imply host sabotage and process resilience support.

Use `artifacts/execution_workflow.json` for machine-readable stage metadata.
