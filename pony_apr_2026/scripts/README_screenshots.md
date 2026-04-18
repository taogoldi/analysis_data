# Screenshot Capture Guide

Sequence for producing the figures used in the Pony blog post.

## Prerequisites
- IDA Pro 7.7+ (tested 7.7, 8.x, 9.x).
- Open the sample `805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236.exe`.
- Let auto-analysis finish (watch the bottom status bar).
- Run `ida_pony_setup.py` once (`File > Script file...`).

## One-shot setup
```
File > Script file... > ida_pony_setup.py
```
Output window should show a block of `[+]` lines with no fatal errors.

---

## ASM screenshots
Open **IDA View-A**, `G`-jump to the address, highlight the instruction range, screenshot the pane.

| # | Jump to | Instructions to include |
|---|---|---|
| 1 | `0x00410329` | `push eax` through `ret` (5 insns) — `pony_entry_trampoline` |
| 2 | `0x00410335` | `call GetTickCount` through `jmp 0x00410335` — `pony_anti_emulation_gate` |
| 3 | `0x0040f759` | `mov eax, fs:[0x30]` through `call 0x40101f` |
| 4 | `0x00403641` | `push 6 / push 1 / push 2 / call socket / cmp eax, -1` |

For #3, after `ida_pony_setup.py` runs the `fs:[0x30]` operand renders as `TEB_MIN.ProcessEnvironmentBlock` — include this in the crop so the reader sees the symbolic offset.

---

## Hex View screenshots
Open **Hex View-1**, `G`-jump, screenshot 1–2 rows of hex + ASCII.

| # | Jump to | Include |
|---|---|---|
| 5 | `0x00402d01` | 16 bytes: `01 23 45 67  89 AB CD EF  FE DC BA 98  76 54 32 10` |
| 6 | `0x00412bdc` | ~12 rows showing `123456\0password\0phpbb\0qwerty\0...` |
| 7 | `Alt-T` → search for `ghbdtn`, screenshot that row + next | Russian-layout tail |
| 8 | `0x00413b68` (approx; `Alt-T` search `POST %s HTTP`) | Full request template |
| 9 | `Alt-T` → `casasferiasacores` | Both `viewtopic.php` URLs |

---

## Decompiled-code screenshots
After `ida_pony_setup.py`, the following functions are renamed and prototyped.  Jump, press `F5`, screenshot the pseudocode pane.

### #10 — MD5 transform
```
G -> md5_transform           (0x00402d3e)
F5
```
Crop top ~30 lines.  You should see round-1 constants `0xD76AA478`, `0xE8C7B756`, `0x242070DB`, `0xC1BDCEEE` and left-shift counts equivalent to 7/12/17/22 (sometimes rendered as `* 0x80`, `* 0x1000`, `* 0x20000`, `* 0x400000`).

### #11 — APLib integrity check
```
G -> aplib_init_with_integrity  (0x0041113d)
F5
```
Crop the first ~20 lines.  The APLib copyright banner appears inline as a string literal inside the XOR loop; the `if (hash != 0) return 0;` guard is the punch line.

### #12 — TCP connect
```
G -> pony_tcp_connect        (0x00403641)
F5
```
Crop the entire function (small — ~130 bytes of ASM, roughly 25 lines of pseudocode).  You should see:
- `socket(2, 1, 6)` — AF_INET / SOCK_STREAM / IPPROTO_TCP
- A local `sockaddr_in` built on the stack
- `connect(s, &sa, 0x10)` returning `-1` on failure

**Manual polish (optional):** in the decompiled view, right-click the local variable used for `sockaddr_in` (default name `v4` / `Dest` / similar) → **Set lvar type...** → enter `struct sockaddr_in`.  This makes `sin_family`, `sin_port`, `sin_addr` appear as field names instead of raw offsets.

---

## If Hex-Rays doesn't pick up the prototype
1. Click on the function name in the pseudocode pane.
2. Press `Y` (Set item type).
3. Paste the prototype from the `PROTOTYPES` list in `ida_pony_setup.py`.
4. Close the decompile tab and re-open with `F5`.

## If renames don't stick
Re-run `ida_pony_setup.py`.  The script is idempotent; `SN_FORCE` overrides any auto-generated name IDA has since reassigned.
