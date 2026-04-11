using System;

namespace Client.Helper;

public interface IClient
{
	bool itsConnect { get; set; }

	void Connect(string ip, string port);

	void Disconnect();

	void ReadData(IAsyncResult ar);
}
