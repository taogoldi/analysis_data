rule MIRAI_LIKE_D40CF9_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "2"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "High-fidelity rule for the analyzed Mirai-like ELF sample"

  strings:
    $s1 = "[*] Connected to authorized server (%s)" ascii
    $s2 = "[!!!] SECURITY ALERT: Command from unauthorized IP: %s (expected: %s)" ascii
    $s3 = "144.172.108.230" ascii
    $s4 = "!SIGKILL" ascii
    $s5 = "1337SoraLOADER" ascii
    $s6 = "method_udpburst" ascii
    $s7 = "[*] Killer thread started." ascii

  condition:
    uint32(0) == 0x464c457f and 5 of ($s*)
}


rule MIRAI_LIKE_D40CF9_STAGE1_VariantHeuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "2"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "Heuristic Mirai-like detector for this cluster family"

  strings:
    $m1 = "udpslam" ascii
    $m2 = "udpburst" ascii
    $m3 = "raknet" ascii
    $m4 = "M-SEARCH * HTTP/1.1" ascii
    $m5 = "Via: SIP/2.0/UDP 192.168.1.1:5060" ascii
    $m6 = "/proc/%s/cmdline" ascii
    $m7 = "/proc/%s/maps" ascii
    $m8 = "/bin/busybox" ascii
    $m9 = "disable_infection_tools" ascii
    $m10 = "scan_and_kill" ascii

  condition:
    uint32(0) == 0x464c457f and
    7 of ($m*)
}


rule MIRAI_LIKE_094E9_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-03-07"
    version = "2"
    sha256 = "094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb"
    description = "High-fidelity rule for the validated Mirai-like variant (094e...)"

  strings:
    $s1 = "watchdog_maintain" ascii
    $s2 = "watchdog_pid" ascii
    $s3 = "udpfl00d" ascii
    $s4 = "tcpFl00d" ascii
    $s5 = "ovhudpflood" ascii
    $s6 = "TSource Engine Query" ascii
    $s7 = "KHserverHACKER" ascii
    $s8 = "/etc/config/resolv.conf" ascii
    $s9 = "__open_nameservers" ascii
    $s10 = "dnslookup.c" ascii

  condition:
    uint32(0) == 0x464c457f and 7 of ($s*)
}


rule MIRAI_LIKE_STAGE1_Family_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-03-07"
    version = "2"
    description = "Family-level heuristic intended to match both d40... and 094e... Mirai-like variants"

  strings:
    $core1 = "/etc/config/resolv.conf" ascii
    $core2 = "__open_nameservers" ascii
    $core3 = "dnslookup.c" ascii
    $core4 = "opennameservers.c" ascii
    $core5 = "__dns_lookup" ascii

    $old1 = "!SIGKILL" ascii
    $old2 = "M-SEARCH * HTTP/1.1" ascii
    $old3 = "Via: SIP/2.0/UDP 192.168.1.1:5060" ascii
    $old4 = "udpburst" ascii
    $old5 = "udpslam" ascii

    $new1 = "watchdog_maintain" ascii
    $new2 = "udpfl00d" ascii
    $new3 = "tcpFl00d" ascii
    $new4 = "ovhudpflood" ascii
    $new5 = "TSource Engine Query" ascii

  condition:
    uint32(0) == 0x464c457f and
    3 of ($core*) and
    (2 of ($old*) or 2 of ($new*))
}
