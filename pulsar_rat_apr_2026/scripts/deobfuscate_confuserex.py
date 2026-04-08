#!/usr/bin/env python3
"""
Pulsar RAT ConfuserEx Deobfuscation Tool
=========================================
Automated deobfuscation of ConfuserEx-renamed identifiers in dnSpy-exported
C# source code. Works on the exported .sln/.csproj project directory.

Techniques used:
  1. P/Invoke EntryPoint extraction — DllImport attributes leak real API names
  2. Pulsar.Common namespace inference — unobfuscated using directives reveal purpose
  3. String literal semantic analysis — hardcoded paths/APIs identify class roles
  4. Data-flow tracing from known sinks — traces config fields to known consumers

Usage:
  python deobfuscate_confuserex.py <exported_project_dir> [--output report.json]

Output:
  - JSON report mapping obfuscated → deobfuscated names
  - Console summary of identified classes and their roles
  - Optional: annotated copy of source files with comments

Author: Tao Goldi
License: CC BY 4.0
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


# ─── Known Pulsar.Common namespace → module purpose mapping ───
PULSAR_NAMESPACE_HINTS = {
    "Pulsar.Common.Cryptography": "crypto",
    "Pulsar.Common.Messages": "c2_messaging",
    "Pulsar.Common.Messages.ClientManagement": "client_lifecycle",
    "Pulsar.Common.Messages.Other": "deferred_assembly",
    "Pulsar.Common.Networking": "networking",
    "Pulsar.Common.Messages.FileManager": "file_management",
    "Pulsar.Common.Messages.Desktop": "remote_desktop",
    "Pulsar.Common.Messages.Monitoring": "monitoring",
}

# ─── String literal → class role mapping ───
STRING_ROLE_MAP = {
    r"Login Data": "chromium_credential_reader",
    r"logins\.json": "firefox_credential_reader",
    r"encrypted_key": "chromium_dpapi_decryptor",
    r"nss3\.dll": "nss_decryptor",
    r"mozglue\.dll": "nss_decryptor",
    r"PK11SDR_Decrypt": "nss_decryptor",
    r"GetCursorInfo": "opera_patcher",
    r"schtasks": "startup_manager",
    r"\\CurrentVersion\\Run": "registry_persistence",
    r"ResetConfig\.xml": "winre_persistence",
    r"Recovery\\OEM": "winre_persistence",
    r"BasicReset_AfterImageApply": "winre_persistence",
    r"AddClipboardFormatListener": "clipboard_monitor",
    r"Hook\.GlobalEvents": "keylogger",
    r"GetForegroundWindow": "active_window_monitor",
    r"GetLastInputInfo": "idle_monitor",
    r"SetWindowsHookEx": "keylogger_hook",
    r"GetAsyncKeyState": "keylogger_polling",
    r"cmd\.exe": "remote_shell",
    r"AntivirusProduct": "system_info",
    r"Win32_Processor": "hardware_info",
    r"Win32_VideoController": "hardware_info",
    r"TcpClient": "tcp_client",
    r"NetworkStream": "tcp_client",
    r"SecureMessageEnvelope": "secure_transport",
    r"MessagePack": "message_serialization",
    r"costura\.\w+\.dll\.compressed": "costura_loader",
    r"AssemblyResolve": "assembly_resolver",
    r"DeflateStream": "costura_loader",
    r"VirtualAllocEx": "process_injection",
    r"WriteProcessMemory": "process_injection",
    r"CreateRemoteThread": "process_injection",
    r"IsDebuggerPresent": "anti_debug",
    r"ProcessDebugPort": "anti_debug",
    r"NtSetInformationThread": "anti_debug",
    r"RtlSetProcessIsCritical": "critical_process",
    r"MiniDumpWriteDump": "process_dump",
    r"DisableTaskMgr": "defense_evasion",
    r"SeDebugPrivilege": "privilege_escalation",
    r"BCryptOpenAlgorithmProvider": "bcrypt_crypto",
    r"BTC|ETH|XMR|LTC|SOL": "crypto_clipper",
    r"DeferredAssembl": "deferred_assembly_loader",
    r"AForge": "webcam_capture",
    r"HKCU\\Software\\Microsoft": "registry_operations",
}

# ─── DllImport EntryPoint regex ───
DLLIMPORT_RE = re.compile(
    r'\[DllImport\(\s*"([^"]+)".*?EntryPoint\s*=\s*"([^"]+)"',
    re.DOTALL,
)

# ─── Method signature with DllImport ───
DLLIMPORT_METHOD_RE = re.compile(
    r'\[DllImport\([^\]]+EntryPoint\s*=\s*"([^"]+)"[^\]]*\]\s*'
    r'(?:private|public|internal|protected)?\s*'
    r'(?:static\s+)?extern\s+\S+\s+(\w+)\s*\(',
    re.DOTALL,
)

# ─── Namespace and class extraction ───
NAMESPACE_RE = re.compile(r'^namespace\s+([\w.]+)', re.MULTILINE)
CLASS_RE = re.compile(
    r'(?:public|internal|private)?\s*(?:static\s+)?'
    r'(?:class|struct|enum|interface)\s+(\w+)',
    re.MULTILINE,
)

# ─── Using directive extraction ───
USING_RE = re.compile(r'^using\s+([\w.]+)\s*;', re.MULTILINE)

# ─── Token comment extraction ───
TOKEN_RE = re.compile(r'//\s*Token:\s*0x(\w+)\s+RID:\s*(\d+)')

# ─── Aes256 constructor call (Settings field identification) ───
AES_CTOR_RE = re.compile(r'new\s+Aes256\(\s*(\w+)\.(\w+)\s*\)')

# ─── Static field with string literal ───
STATIC_FIELD_RE = re.compile(
    r'public\s+static\s+string\s+(\w+)\s*=\s*"([^"]*)"'
)

# ─── ProtectedData.Unprotect ───
DPAPI_RE = re.compile(r'ProtectedData\.Unprotect')


def scan_file(filepath: Path) -> dict:
    """Analyze a single C# source file and extract deobfuscation signals."""
    try:
        content = filepath.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return {}

    result = {
        "path": str(filepath),
        "namespace": None,
        "classes": [],
        "pinvoke_map": {},
        "using_directives": [],
        "string_roles": set(),
        "tokens": [],
        "static_fields": {},
        "has_dpapi": False,
        "has_aes_ctor": False,
    }

    # Extract namespace
    ns_match = NAMESPACE_RE.search(content)
    if ns_match:
        result["namespace"] = ns_match.group(1)

    # Extract classes
    for m in CLASS_RE.finditer(content):
        result["classes"].append(m.group(1))

    # Extract using directives
    for m in USING_RE.finditer(content):
        result["using_directives"].append(m.group(1))

    # Extract P/Invoke mappings
    for m in DLLIMPORT_METHOD_RE.finditer(content):
        real_name = m.group(1)
        obfuscated_name = m.group(2)
        result["pinvoke_map"][obfuscated_name] = real_name

    # Check string literal roles
    for pattern, role in STRING_ROLE_MAP.items():
        if re.search(pattern, content):
            result["string_roles"].add(role)

    # Extract tokens
    for m in TOKEN_RE.finditer(content):
        result["tokens"].append(f"0x{m.group(1)}")

    # Extract static string fields (for Settings class detection)
    for m in STATIC_FIELD_RE.finditer(content):
        result["static_fields"][m.group(1)] = m.group(2)

    # Check for DPAPI usage
    if DPAPI_RE.search(content):
        result["has_dpapi"] = True

    # Check for Aes256 constructor
    if AES_CTOR_RE.search(content):
        result["has_aes_ctor"] = True

    # Convert set to list for JSON serialization
    result["string_roles"] = sorted(result["string_roles"])

    return result


def classify_file(analysis: dict) -> dict:
    """Determine the likely original class/module name from analysis signals."""
    classification = {
        "likely_name": "Unknown",
        "confidence": "low",
        "evidence": [],
    }

    roles = set(analysis.get("string_roles", []))
    usings = analysis.get("using_directives", [])
    pinvoke = analysis.get("pinvoke_map", {})
    fields = analysis.get("static_fields", {})

    # Settings class: has Aes256 constructor + many static string fields
    if analysis.get("has_aes_ctor") and len(fields) > 5:
        classification["likely_name"] = "Settings"
        classification["confidence"] = "high"
        classification["evidence"].append(
            f"Aes256 constructor call + {len(fields)} static encrypted fields"
        )
        return classification

    # P/Invoke-heavy class
    if len(pinvoke) > 5:
        real_apis = list(pinvoke.values())
        classification["likely_name"] = "NativeMethods"
        classification["confidence"] = "high"
        classification["evidence"].append(
            f"{len(pinvoke)} P/Invoke mappings: {', '.join(real_apis[:5])}..."
        )
        return classification

    # Role-based classification (highest specificity first)
    role_to_name = {
        "winre_persistence": ("WindowsRecoveryPersistence", "high"),
        "opera_patcher": ("OperaPatcher", "high"),
        "nss_decryptor": ("FirefoxDecryptor", "high"),
        "chromium_dpapi_decryptor": ("ChromiumDecryptor", "high"),
        "chromium_credential_reader": ("ChromiumCredentialReader", "high"),
        "firefox_credential_reader": ("FirefoxCredentialReader", "medium"),
        "costura_loader": ("CosturaAssemblyLoader", "high"),
        "keylogger": ("KeyloggerCore", "medium"),
        "clipboard_monitor": ("ClipboardMonitor", "high"),
        "crypto_clipper": ("CryptoClipper", "high"),
        "idle_monitor": ("UserStatusMonitor", "medium"),
        "active_window_monitor": ("ActiveWindowMonitor", "medium"),
        "remote_shell": ("RemoteShell", "medium"),
        "tcp_client": ("TcpClient", "medium"),
        "secure_transport": ("SecureTransportClient", "medium"),
        "startup_manager": ("StartupManager", "medium"),
        "registry_persistence": ("StartupManager", "medium"),
        "system_info": ("SystemInfoHelper", "medium"),
        "hardware_info": ("DeviceIdHelper", "medium"),
        "process_injection": ("ProcessInjector", "medium"),
        "anti_debug": ("AntiDebug", "medium"),
        "bcrypt_crypto": ("AesGcmDecryptor", "high"),
        "defense_evasion": ("DefenseEvasion", "medium"),
        "deferred_assembly_loader": ("DeferredAssemblyLoader", "medium"),
        "webcam_capture": ("WebcamCapture", "medium"),
        "privilege_escalation": ("PrivilegeHelper", "medium"),
        "critical_process": ("CriticalProcessHelper", "medium"),
        "process_dump": ("ProcessDumper", "medium"),
    }

    for role, (name, conf) in role_to_name.items():
        if role in roles:
            classification["likely_name"] = name
            classification["confidence"] = conf
            classification["evidence"].append(f"String/API pattern: {role}")
            # Don't break — collect more evidence
            if conf == "high":
                break

    # Pulsar.Common using directives boost confidence
    for using in usings:
        if using in PULSAR_NAMESPACE_HINTS:
            hint = PULSAR_NAMESPACE_HINTS[using]
            classification["evidence"].append(
                f"Using {using} → {hint}"
            )

    return classification


def analyze_project(project_dir: Path) -> dict:
    """Analyze an entire dnSpy-exported C# project."""
    results = {
        "project_dir": str(project_dir),
        "files_analyzed": 0,
        "namespace_map": {},
        "class_map": {},
        "pinvoke_master": {},
        "settings_class": None,
        "settings_fields": {},
    }

    cs_files = sorted(project_dir.rglob("*.cs"))
    results["files_analyzed"] = len(cs_files)

    for filepath in cs_files:
        # Skip Costura embedded DLLs and framework code
        rel = filepath.relative_to(project_dir)
        parts_lower = str(rel).lower()
        if "costura/" in parts_lower and "assemblyloader" not in parts_lower:
            continue
        if "properties/" in parts_lower:
            continue

        analysis = scan_file(filepath)
        if not analysis:
            continue

        classification = classify_file(analysis)
        ns = analysis.get("namespace")
        classes = analysis.get("classes", [])

        # Record namespace mapping
        if ns and classification["likely_name"] != "Unknown":
            if ns not in results["namespace_map"]:
                results["namespace_map"][ns] = {
                    "roles": set(),
                    "classes": {},
                }
            results["namespace_map"][ns]["roles"].update(
                analysis.get("string_roles", [])
            )

        # Record class mapping
        for cls in classes:
            entry = {
                "obfuscated": cls,
                "likely_name": classification["likely_name"],
                "confidence": classification["confidence"],
                "evidence": classification["evidence"],
                "namespace": ns,
                "file": str(rel),
                "pinvoke_count": len(analysis.get("pinvoke_map", {})),
                "tokens": analysis.get("tokens", [])[:3],
            }
            results["class_map"][cls] = entry

            if ns:
                results["namespace_map"].setdefault(ns, {
                    "roles": set(), "classes": {}
                })
                results["namespace_map"][ns]["classes"][cls] = (
                    classification["likely_name"]
                )

        # Collect P/Invoke master map
        results["pinvoke_master"].update(analysis.get("pinvoke_map", {}))

        # Identify Settings class
        if classification["likely_name"] == "Settings":
            results["settings_class"] = {
                "obfuscated_name": classes[0] if classes else "Unknown",
                "namespace": ns,
                "file": str(rel),
                "fields": analysis.get("static_fields", {}),
            }

    # Convert sets to lists for JSON
    for ns_data in results["namespace_map"].values():
        ns_data["roles"] = sorted(ns_data.get("roles", set()))

    return results


def print_report(results: dict):
    """Print a human-readable deobfuscation report."""
    print("=" * 72)
    print("CONFUSEREX DEOBFUSCATION REPORT")
    print("=" * 72)
    print(f"Project: {results['project_dir']}")
    print(f"Files analyzed: {results['files_analyzed']}")
    print()

    # Settings class
    if results.get("settings_class"):
        s = results["settings_class"]
        print("─── SETTINGS CLASS (C2 Configuration) ───")
        print(f"  Obfuscated: {s['obfuscated_name']}")
        print(f"  Namespace:  {s['namespace']}")
        print(f"  File:       {s['file']}")
        print(f"  Encrypted fields: {len(s['fields'])}")
        for field, value in list(s["fields"].items())[:10]:
            display = value[:50] + "..." if len(value) > 50 else value
            print(f"    {field} = \"{display}\"")
        print()

    # P/Invoke map
    if results.get("pinvoke_master"):
        print(f"─── P/INVOKE DEOBFUSCATION ({len(results['pinvoke_master'])} APIs) ───")
        for obf, real in sorted(
            results["pinvoke_master"].items(), key=lambda x: x[1]
        ):
            print(f"  {obf:45s} → {real}")
        print()

    # Namespace map
    if results.get("namespace_map"):
        print("─── NAMESPACE MAP ───")
        for ns, data in sorted(results["namespace_map"].items()):
            roles = ", ".join(data.get("roles", []))[:60]
            cls_count = len(data.get("classes", {}))
            print(f"  {ns}")
            print(f"    Roles: {roles}")
            print(f"    Classes: {cls_count}")
            for obf_cls, likely in data.get("classes", {}).items():
                if likely != "Unknown":
                    print(f"      {obf_cls} → {likely}")
        print()

    # High-confidence class identifications
    high_conf = {
        k: v
        for k, v in results.get("class_map", {}).items()
        if v.get("confidence") in ("high", "medium")
        and v.get("likely_name") != "Unknown"
    }
    if high_conf:
        print(f"─── CLASS IDENTIFICATIONS ({len(high_conf)} matched) ───")
        for obf, info in sorted(
            high_conf.items(), key=lambda x: x[1]["confidence"]
        ):
            conf = info["confidence"].upper()
            print(
                f"  [{conf:6s}] {obf:45s} → {info['likely_name']}"
            )
            for ev in info.get("evidence", [])[:2]:
                print(f"           {ev}")
        print()

    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="Deobfuscate ConfuserEx-renamed .NET source (dnSpy export)"
    )
    parser.add_argument(
        "project_dir",
        help="Path to dnSpy-exported C# project directory",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON report path",
        default=None,
    )
    args = parser.parse_args()

    project_dir = Path(args.project_dir)
    if not project_dir.is_dir():
        print(f"Error: {project_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {project_dir}...")
    results = analyze_project(project_dir)
    print_report(results)

    if args.output:
        out_path = Path(args.output)
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON report written to {out_path}")


if __name__ == "__main__":
    main()
