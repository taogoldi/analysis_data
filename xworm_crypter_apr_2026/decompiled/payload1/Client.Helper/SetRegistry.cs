using Microsoft.Win32;

namespace Client.Helper;

internal class SetRegistry
{
	public static bool CheckValue(string name)
	{
		try
		{
			using RegistryKey registryKey = Registry.CurrentUser.CreateSubKey(Config.RegKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
			if (registryKey.GetValue(name) != null)
			{
				return true;
			}
		}
		catch
		{
		}
		return false;
	}

	public static void SetValue(string name, string value)
	{
		using RegistryKey registryKey = Registry.CurrentUser.CreateSubKey(Config.RegKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
		if (CheckValue(name))
		{
			registryKey.DeleteValue(name);
		}
		registryKey.SetValue(name, value);
	}

	public static string GetValue(string name)
	{
		if (!CheckValue(name))
		{
			return null;
		}
		using RegistryKey registryKey = Registry.CurrentUser.CreateSubKey(Config.RegKey);
		return (string)registryKey.GetValue(name);
	}
}
