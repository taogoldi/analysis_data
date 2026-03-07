# Kaiji Analysis Report

- Sample SHA-256: `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71`
- Size: `2011136` bytes
- Format: `ELF64 x86-64 static Go`

## Key Findings

- Persistence indicators: `20`
- Behavior indicators: `23`
- Base64 decoded candidates: `1`
- C2 candidates: `air.duffy.baby:888, air.xem.lat:25194`
- Persistence script blocks extracted: `8`
- Capability matrix rows: `29`

## Ares/Attack Modules
- `main.Ares_L3_Raw`
- `main.Ares_L3_Raw.func1`
- `main.Ares_L3_Udp`
- `main.Ares_L3_Udp.func1`
- `main.Ares_L3_Udp_Hex`
- `main.Ares_L3_Udp_Hex.func1`
- `main.Ares_Plain_Udp`
- `main.Ares_Plain_Udp.func1`
- `main.Ares_Plain_Udp_Hex`
- `main.Ares_Plain_Udp_Hex.func1`
- `main.Ares_Tcp`
- `main.Ares_Tcp_Hex`
- `main.Ares_Tcp_Keep`
- `main.Ares_Tcp_Keep.func1`
- `main.Ares_Tcp_Keep.func2`
- `main.Ares_Tcp_Keep_Hex`
- `main.Ares_Tcp_Keep_Hex.func1`
- `main.Ares_Tcp_Keep_Hex.func2`
- `main.Ares_Tcp_Read`
- `main.Ares_Tcp_Send`
- `main.Ares_Tcp_Send.func1`
- `main.Ares_Tcp_Send_Hex`
- `main.Ares_Tcp_Send_Hex.func1`
- `main.Ares_ipspoof`
- `main.Ares_ipspoof.func1`
- `main.Ares_send`
- `main.Killcpu`
- `main.Watchdog`
- `main.watchdog`

## Notes
- This pass is static/offline only; no live execution or C2 interaction.
- External IOC `air.duffy.baby:888` was preserved as analyst-provided context.
