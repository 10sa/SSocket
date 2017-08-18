using System;
using System.Security.Cryptography;
using System.IO;

namespace SSocket.Security
{
	class AESManager
	{
		private AesManaged aesManager = new AesManaged();
		private AESManager() { }

		public AESManager(byte[] key)
		{
			aesManager.Padding = PaddingMode.PKCS7;
			aesManager.Mode = CipherMode.CBC;

			byte[] IV = new byte[aesManager.IV.Length];
			aesManager.Key = key;
			Array.Copy(key, IV, IV.Length);

			aesManager.IV = IV;
		}

		public CryptoStream CreateEncryptStream(Stream baseStream)
		{
			return new CryptoStream(baseStream, aesManager.CreateEncryptor(), CryptoStreamMode.Write);
		}

		public CryptoStream CreateDecryptStream(Stream baseStream)
		{
			return new CryptoStream(baseStream, aesManager.CreateDecryptor(), CryptoStreamMode.Read);
		}
	}
}
