# Go Symbol Capability Matrix

- Sample SHA-256: `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71`
- Symbol rows: `29`

## Capability Counts
- `attack_transport_io`: 1
- `ip_spoofing_support`: 2
- `local_resource_exhaustion`: 1
- `self_protection_or_recovery`: 2
- `tcp_flood_module`: 13
- `udp_flood_module`: 8
- `unknown`: 2

## Symbol Matrix

| Symbol | Capability | Surface | Tactic | Confidence |
| --- | --- | --- | --- | --- |
| `main.Ares_L3_Raw` | `unknown` | `unknown` | `unknown` | `low` |
| `main.Ares_L3_Raw.func1` | `unknown` | `unknown` | `unknown` | `low` |
| `main.Ares_L3_Udp` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_L3_Udp.func1` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_L3_Udp_Hex` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_L3_Udp_Hex.func1` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Plain_Udp` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Plain_Udp.func1` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Plain_Udp_Hex` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Plain_Udp_Hex.func1` | `udp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Hex` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep.func1` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep.func2` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep_Hex` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep_Hex.func1` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Keep_Hex.func2` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Read` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Send` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Send.func1` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Send_Hex` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_Tcp_Send_Hex.func1` | `tcp_flood_module` | `network` | `impact` | `medium` |
| `main.Ares_ipspoof` | `ip_spoofing_support` | `network` | `impact` | `medium` |
| `main.Ares_ipspoof.func1` | `ip_spoofing_support` | `network` | `impact` | `medium` |
| `main.Ares_send` | `attack_transport_io` | `network` | `impact` | `low` |
| `main.Killcpu` | `local_resource_exhaustion` | `host` | `impact` | `medium` |
| `main.Watchdog` | `self_protection_or_recovery` | `host` | `defense_evasion` | `low` |
| `main.watchdog` | `self_protection_or_recovery` | `host` | `defense_evasion` | `low` |
