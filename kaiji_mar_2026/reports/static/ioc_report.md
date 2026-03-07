# IOC Report

- Sample SHA-256: `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71`

## C2 Candidates
- `air.duffy.baby:888`
- `air.xem.lat:25194`

## Persistence Paths
- `/boot/System.mod`
- `/etc/crontab`
- `/etc/opt.services.cfg`
- `/etc/profile.d/bash_cfg.sh`
- `/etc/profile.d/gateway.sh`
- `/usr/lib/systemd/system/quotaoff.service`
- `/usr/sbin/ifconfig.cfg`
- `echo "*/1 * * * * root /.mod " >> /etc/crontab`
- `quotaoff.service`
- `systemctl enable quotaoff.service`

## Attack Module Strings
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
