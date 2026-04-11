using System;

namespace Client.Helper;

public class MockClient : Client
{
	public new bool itsConnect { get; set; }

	public new void Connect(string ip, string port)
	{
		itsConnect = true;
		Console.WriteLine("[MockClient] Connected to " + ip + ":" + port);
	}

	public new void Disconnect()
	{
		itsConnect = false;
		Console.WriteLine("[MockClient] Disconnected");
	}

	public new void ReadData(IAsyncResult ar)
	{
		Console.WriteLine("[MockClient] ReadData called");
	}
}
