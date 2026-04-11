using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Client.Helper;

public class DInvokeCore
{
	public static IntPtr GetLibraryAddress(string DLLName, string FunctionName)
	{
		IntPtr loadedModuleAddress = GetLoadedModuleAddress(DLLName);
		if (loadedModuleAddress == IntPtr.Zero)
		{
			throw new DllNotFoundException(DLLName);
		}
		return GetExportAddress(loadedModuleAddress, FunctionName);
	}

	public static IntPtr GetLoadedModuleAddress(string DLLName)
	{
		foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
		{
			if (string.Compare(module.ModuleName, DLLName, ignoreCase: true) == 0)
			{
				return module.BaseAddress;
			}
		}
		return IntPtr.Zero;
	}

	public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
	{
		IntPtr intPtr = IntPtr.Zero;
		try
		{
			int num = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 60));
			Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + num + 20));
			long num2 = ModuleBase.ToInt64() + num + 24;
			long num3 = ((Marshal.ReadInt16((IntPtr)num2) != 267) ? (num2 + 112) : (num2 + 96));
			int num4 = Marshal.ReadInt32((IntPtr)num3);
			int num5 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 16));
			Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 20));
			int num6 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 24));
			int num7 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 28));
			int num8 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 32));
			int num9 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num4 + 36));
			for (int i = 0; i < num6; i++)
			{
				if (Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num8 + i * 4)))).Equals(ExportName, StringComparison.OrdinalIgnoreCase))
				{
					int num10 = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + num9 + i * 2)) + num5;
					int num11 = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + num7 + 4 * (num10 - num5)));
					intPtr = (IntPtr)((long)ModuleBase + num11);
					break;
				}
			}
		}
		catch
		{
			throw new Exception();
		}
		if (intPtr == IntPtr.Zero)
		{
			throw new Exception(ExportName);
		}
		return intPtr;
	}

	public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
	{
		IntPtr libraryAddress = GetLibraryAddress(DLLName, FunctionName);
		if (libraryAddress == IntPtr.Zero)
		{
			throw new Exception();
		}
		return DynamicFunctionInvoke(libraryAddress, FunctionDelegateType, ref Parameters);
	}

	public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
	{
		return Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType).DynamicInvoke(Parameters);
	}
}
