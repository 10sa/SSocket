﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSocketLib.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.IO;
using System.Net;
using System.Security;

using SSocketLib.Collections;
using SSocketLib.Enums;

namespace SSocketLib.Net.Tests
{
	[TestClass()]
	public class SSocketTests
	{
		private const string TestMessage = "TEST MESSAGE!";
		private readonly byte[] TestData = new byte[128];

		[TestMethod()]
		public void SendTest()
		{
			SSocket serverSocket = new SSocket();
			serverSocket.Bind(new IPEndPoint(IPAddress.Any, 45050), 5);

			RunClientThread();

			SSocket clientSocket = serverSocket.Accept();
			SSocketPacket packet = clientSocket.ReceivePacket();
			clientSocket.Import(packet);

			clientSocket.BeginReceive();
			using (BinaryReader reader = clientSocket.Receive(packet.GetPacketDataSize()))
			{
				byte[] readedData = reader.ReadBytes(TestData.Length);
				Assert.IsTrue(readedData.SequenceEqual(TestData));
			}
		}

		private void RunClientThread()
		{
			Thread clientThread = new Thread(ClientThread);
			clientThread.Start();
		}

		private void ClientThread()
		{
			SSocket clientSocket = new SSocket();
			clientSocket.Connect(new IPEndPoint(IPAddress.Loopback, 45050));

			clientSocket.BeginSend();
			clientSocket.StackData(TestData, 0, TestData.Length);
			clientSocket.Send();
		}

		[TestMethod()]
		public void RemoveExtraDataBitTest()
		{
			SSocket socket = new SSocket();
			socket.SetExtraDataBit((long)SSocketExtraDataBit.StartSegmentation);
			socket.RemoveExtraDataBit((long)SSocketExtraDataBit.StartSegmentation);
			Assert.AreEqual(socket.ExtraDataBit, 0);
		}
	}
}