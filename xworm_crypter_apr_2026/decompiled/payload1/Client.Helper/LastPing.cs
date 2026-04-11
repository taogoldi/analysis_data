using System;
using System.Threading;

namespace Client.Helper;

public class LastPing
{
	private Timer timer;

	private long ticks;

	public LastPing(Client client)
	{
		ticks = DateTime.Now.Ticks;
		timer = new Timer(Check, client, 0, 6000);
	}

	private int DiffSeconds(long startTime, DateTime endTime)
	{
		return (int)Math.Abs(new TimeSpan(endTime.Ticks - startTime).TotalSeconds);
	}

	private void Check(object obj)
	{
		if (DiffSeconds(ticks, DateTime.Now) > 60)
		{
			((Client)obj).Disconnect();
		}
	}

	public void Disconnect()
	{
		if (timer != null)
		{
			timer.Dispose();
		}
	}

	public void Last()
	{
		ticks = DateTime.Now.Ticks;
	}
}
