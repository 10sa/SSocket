using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSocket.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.IO;
using System.Net;

using SSocket.Collections;
using SSocket.Enums;

namespace SSocket.Net.Tests
{
	[TestClass()]
	public class SSocketTests
	{
		private const string TestMessage = "TEST MESSAGE!";

		[TestMethod()]
		public void SendTest()
		{
			Thread clientThread = new Thread(new ThreadStart(ClientThread));
			clientThread.Start();

			SSocket serverSocket = new SSocket();
			serverSocket.Bind(new IPEndPoint(IPAddress.Any, 45050), 5);

			SSocket clientSocket = serverSocket.Accept();
			SSocketPacket packet = clientSocket.ReceivePacket();
			clientSocket.BeginReceive();

			using (BinaryReader reader = clientSocket.Receive(packet.GetPacketDataSize()))
			{
				Assert.IsTrue(string.Equals(TestMessage, Encoding.UTF8.GetString(reader.ReadBytes((int)packet.GetPacketDataSize()))));
			}
		}

		private void ClientThread()
		{
			SSocket clientSocket = new SSocket();
			clientSocket.Connect(new IPEndPoint(IPAddress.Loopback, 45050));

			byte[] messange = Encoding.UTF8.GetBytes(TestMessage);
			clientSocket.Send(messange, messange.Length);
		}

		[TestMethod()]
		public void RemoveExtraDataBitTest()
		{
			SSocket socket = new SSocket();
			socket.SetExtraDataBit((long)SSocketExtraDataBit.SegmentPacket);
			socket.RemoveExtraDataBit((long)SSocketExtraDataBit.SegmentPacket);

			Assert.AreEqual(socket.ExtraDataBit, 0);
		}
	}
}