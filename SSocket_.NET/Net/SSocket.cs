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
	/// <summary>
	/// Implements the SSocket protocol socket interface.
	/// </summary>
	public sealed class SSocket
	{
		#region Private variables
		private const int IOBufferLength = 2048;

		private ECDiffieHellmanCng keyExchanger = new ECDiffieHellmanCng();
		private AESManager aesManager;
		private Socket socket;
		#endregion

		#region Public Propertys
		/// <summary>
		/// Diff-Hellman Algorithms's public key.
		/// </summary>
		public byte[] PublicKey { get; private set; }

		/// <summary>
		/// Derived by Diff-Hellman share key.
		/// </summary>
		public byte[] ShareKey { get; private set; }

		/// <summary>
		/// Protocol 64bit option for additional data packets.
		/// </summary>
		public long ExtraDataBit { get; set; }
		#endregion

		#region Constructors
		/// <summary>
		/// Create new SSocket instance.
		/// </summary>
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
		#endregion

		/// <summary>
		/// Attempt to connect using the SSocket protocol.
		/// </summary>
		/// <param name="endpoint">An EndPoint that represents the remote device.</param>
		public void Connect(EndPoint endpoint)
		{
			try
			{
				socket.Connect(endpoint);
				socket.Send(new SSocketPacket(SSocketPacketType.ClientHello, PublicKey.LongLength).GetBytes());
				socket.Send(PublicKey);

				ReceiveHelloPacket(socket, SSocketPacketType.ServerHello);
			}
			catch (Exception) {
				throw;
			}
		}

		/// <summary>
		/// Associates a Socket with a local endpoint and places a socket in a listening state.
		/// </summary>
		/// <param name="endpoint">The local EndPoint to associate with the Socket.</param>
		/// <param name="backlog">The maximum length of the pending connections queue. if value is 0, not set listening state.</param>
		public void Bind(EndPoint endpoint, int backlog)
		{
			socket.Bind(endpoint);

			if (backlog > 0)
				socket.Listen(backlog);
		}

		/// <summary>
		/// Creates a new SSocket for a newly created connection.
		/// </summary>
		/// <returns>A SSocket for a newly created connection.</returns>
		public SSocket Accept()
		{
			Socket clientSocket = socket.Accept();
			clientSocket.Send(new SSocketPacket(SSocketPacketType.ServerHello, PublicKey.LongLength).GetBytes());
			clientSocket.Send(PublicKey);

			ReceiveHelloPacket(clientSocket, SSocketPacketType.ClientHello);
			return new SSocket(ShareKey, clientSocket);
		}

		#region Encrypt Send Part
		private CryptoStream encryptCryptoStream;

		/// <summary>
		/// Begin SSocket protocol sending progress.
		/// </summary>
		/// <returns>The stream that stores the data to be sent.</returns>
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

		/// <summary>
		/// Writes a sequence of bytes to the current data store stream and advances the current position within the stream by the number of bytes written.
		/// </summary>
		/// <param name="buffer">An array of bytes. This method copies count bytes from buffer to the current stream.</param>
		/// <param name="offset">The byte offset in buffer at which to begin copying bytes to the current stream.</param>
		/// <param name="length">The number of bytes to be written to the current stream.</param>
		public void StackData(byte[] buffer, int offset, int length)
		{
			if (encryptCryptoStream != null)
				encryptCryptoStream.Write(buffer, offset, length);
			else
				throw new InvalidOperationException("Not initalized.");
		}

		/// <summary>
		/// Sends data written to internal storage to the associated Socket using the specified ExtraDataBit.
		/// </summary>
		public void Send()
		{
			encryptCryptoStream.FlushFinalBlock();
			encryptCryptoStream.Dispose();

			encryptCryptoStream = null;
			using (BinaryReader reader = new BinaryReader(File.Open(GetCacheFilePath("send"), FileMode.Open)))
			{
				byte[] buffer = new byte[IOBufferLength];
				long leftFileSize = reader.BaseStream.Length;
				socket.Send(new SSocketPacket(SSocketPacketType.Data, leftFileSize, ExtraDataBit).GetBytes());

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

		/// <summary>
		/// Send a data to byte array, this method does not guarantee stability for large data.
		/// </summary>
		/// <param name="buffer">Data.to send.</param>
		public void Send(byte[] buffer, int length)
		{
			MemoryStream memoryStream = new MemoryStream();
			CryptoStream cryptoStream = aesManager.CreateEncryptStream(memoryStream);
			cryptoStream.Write(buffer, 0, buffer.Length);
			cryptoStream.FlushFinalBlock();

			byte[] encryptedData = memoryStream.ToArray();

			socket.Send(new SSocketPacket(SSocketPacketType.Data, encryptedData.Length, ExtraDataBit).GetBytes());
			socket.Send(encryptedData, encryptedData.Length, SocketFlags.None);

			cryptoStream.Dispose();
			memoryStream.Dispose();
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

		/// <summary>
		/// Closes the socket connection and allows reuse of the socket.
		/// </summary>
		/// <param name="reuseSocket">true if this socket can be reused after the current connection is closed; otherwise, false.</param>
		public void Disconnect(bool reuseSocket)
		{
			socket.Disconnect(reuseSocket);
		}

		/// <summary>
		/// Receive from socket to SSocket packet.
		/// </summary>
		/// <returns>Received SSocket packet.</returns>
		/// <exception cref="ArgumentException">Received wrong data from socket.</exception>
		public SSocketPacket ReceivePacket()
		{
			byte[] buffer = new byte[SSocketPacket.GetPacketSize()];
			ReceiveFromSocket(socket, buffer.Length, buffer);

			SSocketPacket helloPacket = SSocketPacket.Parse(buffer);
			return helloPacket;
		}

		#region Private methods.
		private static SSocketPacket ReceivePacket(Socket socket)
		{
			byte[] buffer = new byte[SSocketPacket.GetPacketSize()];
			ReceiveFromSocket(socket, buffer.Length, buffer);

			SSocketPacket helloPacket = SSocketPacket.Parse(buffer);
			return helloPacket;
		}

		private void ReceiveHelloPacket(Socket socket, SSocketPacketType helloType)
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

		private bool IsValidPacket(SSocketPacket packet, SSocketPacketType type)
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

		private static void ReceiveFromSocket(Socket socket, int size, byte[] buffer)
		{
			int receivedSize = 0;
			do
				receivedSize += socket.Receive(buffer, (int)receivedSize, size - receivedSize, SocketFlags.None);
			while (receivedSize < size);
		}
		#endregion
	}
}
