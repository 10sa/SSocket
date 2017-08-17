using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Security;
using System.IO;

using SSocket.Security;
using SSocket.Enums;
using SSocket.Collections;

namespace SSocket.Net
{
	public sealed class SSocket
	{
		public byte[] PublicKey { get; private set; }
		public byte[] ShareKey { get; private set; }

		private ECDiffieHellmanCng keyExchanger = new ECDiffieHellmanCng();
		private AESManager aesManager;
		private Socket socket;

		public SSocket()
		{
			socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
			keyExchanger.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			keyExchanger.HashAlgorithm = CngAlgorithm.Sha256;
			PublicKey = keyExchanger.PublicKey.ToByteArray();
		}

		private SSocket (byte[] shareKey, Socket clientSocket)
		{
			socket = clientSocket;
			ShareKey = shareKey;

			aesManager = new AESManager(ShareKey);
		}

		public void Connect(EndPoint endpoint)
		{
			try
			{
				socket.Connect(endpoint);
				socket.Send(new SSocketPacket(SSocket_PacketType.ClientHello, PublicKey.LongLength).GetBytes());
				socket.Send(PublicKey);

				ReceiveHelloPacket(socket, SSocket_PacketType.ServerHello);
			}
			catch (Exception) {
				throw;
			}
		}

		public void Bind(EndPoint endpoint, int backlog)
		{
			socket.Bind(endpoint);

			if (backlog > 0)
				socket.Listen(backlog);
		}

		public SSocket Accept()
		{
			Socket clientSocket = socket.Accept();
			clientSocket.Send(new SSocketPacket(SSocket_PacketType.ServerHello, PublicKey.LongLength).GetBytes());
			clientSocket.Send(PublicKey);

			ReceiveHelloPacket(clientSocket, SSocket_PacketType.ClientHello);
			return new SSocket(ShareKey, clientSocket);
		}

		private const int IOBufferLength = 2048;

		#region Encrypt Send Part
		private CryptoStream encryptCryptoStream;

		public CryptoStream BeginSend()
		{
			if (encryptCryptoStream == null)
			{
				encryptCryptoStream = aesManager.CreateEncryptStream(File.Create(GetCacheFilePath("Send"), 2048, FileOptions.None));
				return encryptCryptoStream;
			}
			else
				throw new InvalidOperationException("Already initalized..");
		}

		public void StackData(byte[] buffer, int offset, int length)
		{
			if (encryptCryptoStream != null)
				encryptCryptoStream.Write(buffer, offset, length);
			else
				throw new InvalidOperationException("Not initalized.");
		}

		public void Send()
		{
			encryptCryptoStream.FlushFinalBlock();
			encryptCryptoStream.Dispose();

			encryptCryptoStream = null;
			using (BinaryReader reader = new BinaryReader(File.Open(GetCacheFilePath("send"), FileMode.Open)))
			{
				byte[] buffer = new byte[IOBufferLength];
				long leftFileSize = reader.BaseStream.Length;
				socket.Send(new SSocketPacket(SSocket_PacketType.Data, leftFileSize).GetBytes());

				int readedSize;
				do
				{
					readedSize = reader.Read(buffer, 0, buffer.Length);
					socket.Send(buffer, readedSize, SocketFlags.None);
					leftFileSize -= readedSize;
				}
				while (leftFileSize > 0);
			}

			File.Delete(GetCacheFilePath("send"));
		}
		#endregion

		#region Decrypt Receive Part
		private FileStream decryptingCacheStream;

		public void BeginReceive()
		{
			decryptingCacheStream = File.Create(GetCacheFilePath("EncryptedReceive"), IOBufferLength, FileOptions.None);
		}

		public BinaryReader Receive(long dataSize)
		{
			ReceiveEncryptedData(dataSize);

			FileStream decryptCacheStream = File.Create("DencryptedReceive", 2048, FileOptions.DeleteOnClose);
			BinaryWriter decryptDataStream = new BinaryWriter(decryptCacheStream);
			using (CryptoStream decryptingCryptoStream = aesManager.CreateDecryptStream(decryptingCacheStream))
			{
				byte[] IOBuffer = new byte[IOBufferLength];
				int readedSize;

				while ((readedSize = decryptingCryptoStream.Read(IOBuffer, 0, IOBuffer.Length)) > 0)
					decryptDataStream.Write(IOBuffer, 0, readedSize);
			}

			decryptingCacheStream.Dispose();
			decryptCacheStream.Position = 0;
			return new BinaryReader(decryptCacheStream);
		}

		private void ReceiveEncryptedData(long dataSize)
		{
			byte[] IOBuffer = new byte[IOBufferLength];

			int readedSize;
			long leftDataSize = dataSize;
			do
			{
				readedSize = socket.Receive(IOBuffer, dataSize > int.MaxValue ? int.MaxValue : (int)dataSize, SocketFlags.None);
				decryptingCacheStream.Write(IOBuffer, 0, readedSize);

				leftDataSize -= readedSize;
			}
			while (leftDataSize > 0);
			decryptingCacheStream.Flush();
			decryptingCacheStream.Position = 0;
		}
		#endregion

		public void Disconnect(bool reuseSocket)
		{
			socket.Disconnect(reuseSocket);
		}

		public SSocketPacket ReceivePacket()
		{
			byte[] buffer = new byte[SSocketPacket.GetPacketSize()];
			ReceiveFromSocket(socket, buffer.Length, buffer);

			SSocketPacket helloPacket = SSocketPacket.Parse(buffer);
			return helloPacket;
		}

		private SSocketPacket ReceivePacket(Socket socket)
		{
			byte[] buffer = new byte[SSocketPacket.GetPacketSize()];
			ReceiveFromSocket(socket, buffer.Length, buffer);

			SSocketPacket helloPacket = SSocketPacket.Parse(buffer);
			return helloPacket;
		}

		private void ReceiveHelloPacket(Socket socket, SSocket_PacketType helloType)
		{
			try
			{
				SSocketPacket helloPacket = ReceivePacket(socket);
				if (IsValidPacket(helloPacket, helloType))
					CreateShareKey(socket, helloPacket);
			}
			catch (Exception)
			{
				throw new InvalidOperationException("Client is not used ssocket.");
			}
		}
		private string GetCacheFilePath(string subPath = "")
		{
			return string.Format("cache{0}{1}.cache", Environment.CurrentManagedThreadId, subPath);
		}

		private bool IsValidPacket(SSocketPacket packet, SSocket_PacketType type)
		{
			if (packet.GetPacketType() == type && packet.GetPacketDataSize() == PublicKey.LongLength)
				return true;
			else
				throw new SecurityException("Client is send wrong packet.");
		}

		private void CreateShareKey(Socket socket, SSocketPacket serverHelloPacket)
		{
			byte[] serverPublicKey = new byte[serverHelloPacket.GetPacketDataSize()];
			ReceiveFromSocket(socket, (int)serverHelloPacket.GetPacketDataSize(), serverPublicKey);

			ShareKey = keyExchanger.DeriveKeyMaterial(CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob));
			aesManager = new AESManager(ShareKey);
		}

		private void  ReceiveFromSocket(Socket socket, int size, byte[] buffer)
		{
			int receivedSize = 0;
			do
				receivedSize += socket.Receive(buffer, (int)receivedSize, size - receivedSize, SocketFlags.None);
			while (receivedSize < size);
		}
	}
}
