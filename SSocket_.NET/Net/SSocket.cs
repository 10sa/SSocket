using System;
using System.Net.Sockets;
using System.Threading;
using System.Net;
using System.Security.Cryptography;
using System.Security;
using System.IO;

using SSocketLib.Security;
using SSocketLib.Enums;
using SSocketLib.Collections;

namespace SSocketLib.Net
{
	/// <summary>
	/// Implements the SSocket protocol socket interface. This class cannot be inherited.
	/// </summary>
	public sealed class SSocket : IDisposable
	{
		#region Private variables
		private const int IOBufferLength = 2048;

		private ECDiffieHellmanCng keyExchanger = new ECDiffieHellmanCng();
		private AESManager aesManager;
		private Socket socket;

		private bool isSegmentation = false;
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
		public long ExtraDataBit  { get; private set; }

		/// <summary>
		/// Limits the maximum size of packet data.If data larger than this size is input, it is divided and transmitted. If 0, there is no limit.
		/// </summary>
		public long PacketMaxSize { get; set; }

		/// <summary>
		/// Gets a value that indicates whether a Socket is connected to a remote host as of the last Send or Receive operation.
		/// </summary>
		public bool Connected { get { return socket.Connected; } }
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

		#region Public methods
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

		/// <summary>
		/// Closes the socket connection and allows reuse of the socket.
		/// </summary>
		/// <param name="reuseSocket">true if this socket can be reused after the current connection is closed; otherwise, false.</param>
		public void Disconnect(bool reuseSocket)
		{
			socket.Disconnect(reuseSocket);
		}

		/// <summary>
		/// Sets the EDB (Extra Data Bit) of the SSocket EDB property.
		/// </summary>
		/// <param name="edb">The EDB value to set.</param>
		public void SetExtraDataBit(params long[] edb)
		{
			foreach (var dataBit in edb)
				ExtraDataBit = ExtraDataBit | dataBit;
		}

		/// <summary>
		/// Removes the EDB (Extra Data Bit) of the SSocket EDB property.
		/// </summary>
		/// <param name="edb"></param>
		public void RemoveExtraDataBit(params long[] edb)
		{
			foreach (var dataBit in edb)
				ExtraDataBit = ExtraDataBit & ~dataBit;
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

		/// <summary>
		/// Socket info import from SSocketPacket class to SSocket.
		/// </summary>
		/// <param name="packet">SSocketPacket class to import.</param>
		public void Import(SSocketPacket packet)
		{
			ExtraDataBit = packet.GetPacketExtraDataBit();
			receiveDataSize = packet.GetPacketDataSize();
			isSegmentation = packet.HasExtraDataBit(SSocketExtraDataBit.StartSegmentation);
		}

		/// <summary>
		/// Gets the remote endpoint.
		/// </summary>
		/// <returns>The EndPoint with which the Socket is communicating.</returns>
		public EndPoint GetRemoteEndPoint()
		{
			return socket.RemoteEndPoint;
		}

		/// <summary>
		/// Releases all resources used by the current instance of the SSocket class.
		/// </summary>
		public void Dispose()
		{
			socket.Dispose();
			aesManager.Dispose();
			keyExchanger.Dispose();
		}
		#endregion

		#region Encrypt Send Part
		private CryptoStream encryptCryptoStream;
		private long stackedDataSize;
		private SSocketPacketType sendType;
		private object sendLocker = new object();

		/// <summary>
		/// Start sending SSocket protocol.
		/// </summary>
		/// <returns>The stream that stores the data to be sent.</returns>
		public CryptoStream BeginSend(SSocketPacketType type = SSocketPacketType.Data)
		{
			return InitEncryptSend(type);
		}

		/// <summary>
		/// Start sending SSocket protocol.
		/// </summary>
		/// <returns>The stream that stores the data to be sent.</returns>
		public CryptoStream BeginSend(long type = (long)SSocketPacketType.Data)
		{
			return InitEncryptSend(Int64ToSSocketPacketType(type));
		}

		private CryptoStream InitEncryptSend(SSocketPacketType type)
		{
			Monitor.Enter(sendLocker);

			if (encryptCryptoStream == null)
			{
				encryptCryptoStream = aesManager.CreateEncryptStream(File.Create(GetCacheFilePath("Send"), 2048, FileOptions.None));
				sendType = type;

				if (HasExtraDataBit(SSocketExtraDataBit.StartSegmentation))
				{
					SendPacket(type);

					SetExtraDataBit((long)SSocketExtraDataBit.SegmentPacket);
					RemoveExtraDataBit((long)SSocketExtraDataBit.StartSegmentation);

					stackedDataSize = 0;
				}

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
			{
				if (stackedDataSize + length <= PacketMaxSize)
				{
					encryptCryptoStream.Write(buffer, offset, length);
					stackedDataSize += length;
				}
				else
				{
					int writeLength = (int)(length + stackedDataSize - PacketMaxSize);
					int rewriteLength = length - writeLength;

					encryptCryptoStream.Write(buffer, offset, writeLength);
					Send();

					BeginSend(sendType);
					encryptCryptoStream.Write(buffer, writeLength, rewriteLength);
				}
			}
			else
				throw new InvalidOperationException("Not initalized.");
		}

		/// <summary>
		/// Sends data written to internal storage to the associated Socket using the specified ExtraDataBit.
		/// </summary>
		public void Send()
		{
			if (stackedDataSize > 0)
			{
				encryptCryptoStream.FlushFinalBlock();
				encryptCryptoStream.Dispose();

				encryptCryptoStream = null;
				using (BinaryReader reader = new BinaryReader(File.Open(GetCacheFilePath("Send"), FileMode.Open)))
				{
					byte[] buffer = new byte[IOBufferLength];
					long leftFileSize = reader.BaseStream.Length;
					socket.Send(new SSocketPacket(sendType, leftFileSize, ExtraDataBit).GetBytes());

					int readedSize;
					do
					{
						readedSize = reader.Read(buffer, 0, buffer.Length);
						socket.Send(buffer, readedSize, SocketFlags.None);
						leftFileSize -= readedSize;
					}
					while (leftFileSize > 0);
				}
			}

			Monitor.Exit(sendLocker);
			File.Delete(GetCacheFilePath("Send"));
		}

		/// <summary>
		/// Send a data to byte array, this method does not guarantee stability for large data and not support segmentation send.
		/// </summary>
		/// <param name="buffer">Data.to send.</param>
		public void Send(byte[] buffer, int length, long packetType = (long)SSocketPacketType.Data)
		{
			Monitor.Enter(sendLocker);
			MemoryStream memoryStream = new MemoryStream();
			CryptoStream cryptoStream = aesManager.CreateEncryptStream(memoryStream);
			cryptoStream.Write(buffer, 0, buffer.Length);
			cryptoStream.FlushFinalBlock();

			byte[] encryptedData = memoryStream.ToArray();

			socket.Send(new SSocketPacket(packetType, encryptedData.Length, ExtraDataBit & ~(long)SSocketExtraDataBit.StartSegmentation).GetBytes());
			socket.Send(encryptedData, encryptedData.Length, SocketFlags.None);

			cryptoStream.Dispose();
			memoryStream.Dispose();
			Monitor.Exit(sendLocker);
		}
		#endregion

		#region Decrypt Receive Part
		private FileStream decryptingCacheStream;
		private long receiveDataSize;
		private object receiveLocker = new object();

		/// <summary>
		/// Start receiving SSocket protocol.
		/// </summary>
		public void BeginReceive()
		{
			if (decryptingCacheStream == null)
			{
				decryptingCacheStream = File.Create(GetCacheFilePath("EncryptedReceive"), IOBufferLength, FileOptions.DeleteOnClose);
				Monitor.Enter(receiveLocker);
			}
			else
				throw new InvalidOperationException("Already Initalized.");
		}

		/// <summary>
		/// It receives and decrypts the encrypted data using the given encrypted data size, writes it to the stream.
		/// </summary>
		/// <param name="dataSize">Data to size.</param>
		/// <returns>The stream in which the data was written.</returns>
		public BinaryReader Receive(long dataSize)
		{
			if (decryptingCacheStream != null)
			{
				FileStream decryptCacheStream = File.Create(GetCacheFilePath("DencryptedReceive"), 2048, FileOptions.DeleteOnClose);

				if (isSegmentation)
				{
					long readedDataSize = 0;
					do
					{
						SSocketPacket segment = ReceivePacket();
						if (segment.HasExtraDataBit(SSocketExtraDataBit.SegmentPacket))
							ReceiveEncryptedBytes(segment.GetPacketDataSize());
						else
							throw new SecurityException("Received wrong packet.");

						readedDataSize += DecryptCryptoStreamData(decryptCacheStream, segment.GetPacketDataSize());
						BeginReceive();
					}
					while (readedDataSize < dataSize);
				}
				else
				{
					ReceiveEncryptedBytes(dataSize);
					DecryptCryptoStreamData(decryptCacheStream, dataSize);
				}

				decryptCacheStream.Position = 0;
				Monitor.Exit(receiveLocker);
				return new BinaryReader(decryptCacheStream);
			}
			else
				throw new InvalidOperationException("Not initalized.");
		}

		private int DecryptCryptoStreamData(FileStream decryptCacheStream, long dataSize)
		{
			this.receiveDataSize = dataSize;
			int decryptedSize = 0;

			BinaryWriter decryptDataStream = new BinaryWriter(decryptCacheStream);
			using (CryptoStream decryptingCryptoStream = aesManager.CreateDecryptStream(decryptingCacheStream))
			{
				byte[] IOBuffer = new byte[IOBufferLength];
				int readedSize;

				while ((readedSize = decryptingCryptoStream.Read(IOBuffer, 0, IOBuffer.Length)) > 0)
				{
					decryptDataStream.Write(IOBuffer, 0, readedSize);
					decryptedSize += readedSize;
				}
			}

			decryptingCacheStream.Dispose();
			decryptingCacheStream = null;

			return decryptedSize;
		}

		private void ReceiveEncryptedBytes(long dataSize)
		{
			byte[] IOBuffer = new byte[IOBufferLength];

			int readedSize;
			long leftDataSize = dataSize;
			do
			{
				readedSize = socket.Receive(IOBuffer, Math.Min(dataSize > int.MaxValue ? int.MaxValue : (int)dataSize, IOBuffer.Length), SocketFlags.None);
				decryptingCacheStream.Write(IOBuffer, 0, readedSize);

				leftDataSize -= readedSize;
			}
			while (leftDataSize > 0);
			decryptingCacheStream.Position = 0;
		}
		#endregion

		#region Private methods.
		private SSocketPacket ReceivePacket(Socket socket)
		{
			byte[] buffer = new byte[SSocketPacket.GetPacketSize()];
			ReceiveFromSocket(socket, buffer.Length, buffer);

			SSocketPacket helloPacket = SSocketPacket.Parse(buffer);

			if ((helloPacket.GetPacketExtraDataBit() & (long)SSocketExtraDataBit.StartSegmentation) > 0)
				isSegmentation = true;

			return helloPacket;
		}

		private SSocketPacketType Int64ToSSocketPacketType(long type)
		{
			return (SSocketPacketType)Enum.Parse(typeof(SSocketPacketType), type.ToString());
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

		private void SendPacket(Socket socket, SSocketPacketType type)
		{
			socket.Send(new SSocketPacket(type, receiveDataSize, ExtraDataBit).GetBytes());
		}

		private void SendPacket(SSocketPacketType type)
		{
			socket.Send(new SSocketPacket(type, receiveDataSize, ExtraDataBit).GetBytes());
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

		private bool HasExtraDataBit(SSocketExtraDataBit edb)
		{
			return (ExtraDataBit & (long)edb) > 0 ? true : false;
		}
		#endregion
	}
}
