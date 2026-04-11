using System;

namespace Client.Helper;

internal static class PolymorphArea
{
	private static int state;

	public static void Touch()
	{
		try
		{
			int tickCount = Environment.TickCount;
			tickCount ^= 0x5A5A5A5A;
			tickCount = (tickCount << 3) | (tickCount >>> 29);
			state ^= tickCount;
			if ((state & 1) == 0)
			{
				state ^= 305419896;
			}
		}
		catch
		{
		}
	}

	public static int GetState()
	{
		return state;
	}
}
