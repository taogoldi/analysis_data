using System;
using System.Text;

namespace Client.Helper;

internal class EncryptString
{
	public static string enc = "m)L\"Z67:%HSgE[K$R~@}t&wJY/o9{D]vIO5hQs8#C2a>*^fPjM;G4lnXAk_ iq?d-yxz'p<u|=U1TW.V+B,`Nr0e\\Fc(!3b";

	public static string dec = "(ShC8W0~mG!j4<=F7'IzEvXRZyba[KQ52e?\">t$H#@;D|q`p+]J),u\\6w_Y{nMBkf9o31O-UL.gdr%ixP^TNsl&AV/} *c:";

	public static string Decode(string text)
	{
		if (string.IsNullOrEmpty(text))
		{
			return text;
		}
		if (text.StartsWith("%") && text.EndsWith("%"))
		{
			return text;
		}
		string text2 = enc ?? string.Empty;
		if (string.IsNullOrEmpty(text2) || text2 == "m)L\"Z67:%HSgE[K$R~@}t&wJY/o9{D]vIO5hQs8#C2a>*^fPjM;G4lnXAk_ iq?d-yxz'p<u|=U1TW.V+B,`Nr0e\\Fc(!3b")
		{
			return text;
		}
		byte[] array;
		try
		{
			array = Convert.FromBase64String(text);
		}
		catch
		{
			return text;
		}
		byte[] bytes = Encoding.UTF8.GetBytes(text2);
		byte[] array2 = new byte[array.Length];
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)(array[i] ^ bytes[i % bytes.Length]);
		}
		return Encoding.UTF8.GetString(array2);
	}
}
