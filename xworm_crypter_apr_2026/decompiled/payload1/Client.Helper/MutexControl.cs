using System.Threading;

namespace Client.Helper;

public static class MutexControl
{
	public static Mutex currentApp;

	public static bool createdNew;

	public static bool CreateMutex(string mtx)
	{
		try
		{
			if (string.IsNullOrEmpty(mtx))
			{
				createdNew = true;
				return true;
			}
			currentApp = new Mutex(initiallyOwned: false, mtx, out createdNew);
			if (!createdNew)
			{
				currentApp.Close();
				currentApp = null;
			}
			return createdNew;
		}
		catch
		{
			createdNew = true;
			return true;
		}
	}

	public static void Exit()
	{
		if (currentApp != null)
		{
			currentApp.Dispose();
		}
	}
}
