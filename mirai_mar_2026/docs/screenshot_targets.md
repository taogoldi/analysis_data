# Suggested Screenshot Targets (IDA)

Use these for a future write-up with concrete visuals:

1. `main` command parser and dispatch
   - File: `d40cf9...c28.elf`
   - Offset/VA: `0x400412` through `0x400703`
   - Why: shows `!SIGKILL` gate + method command dispatch to `method_*`

2. C2 verification path
   - Function: `verify_server_ip` (`0x4001c0`)
   - String: authorized IP at `0x41498a` (`144.172.108.230`)
   - Why: proves connection is bound to a hardcoded peer IP

3. Killer loop
   - Function: `killer_thread_func` (`0x400730`)
   - Why: shows periodic anti-competition cycle

4. Infection-tool disable list
   - Function: `disable_infection_tools` (`0x400a10`)
   - Strings near `0x414b48` .. `0x414ba8`
   - Why: shows downloader binary path hardening/removal behavior

5. Process scan-and-kill behavior
   - Function: `scan_and_kill` (`0x400d60`)
   - Why: shows `/proc` traversal and kill-on-match logic

6. One attack method worker
   - Function: `method_udpburst` (`0x400f60`) and `udpburst_worker`
   - Why: concrete flood implementation evidence

