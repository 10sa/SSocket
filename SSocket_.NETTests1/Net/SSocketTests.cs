using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSocketLib.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net;

namespace SSocketLib.Net.Tests
{
	[TestClass()]
	public class SSocketTests
	{
		private const string TestMessage = "LARGE MESSAGE TESTING";
		[TestMethod()]
		public void CalcMemoryBlockSize()
		{
			SSocket socket = new SSocket();
			SSocket serverSocket = new SSocket();

			serverSocket.Bind(new IPEndPoint(IPAddress.Any, 12345), 10);
			new Thread(() => { serverSocket.Accept(); }).Start();
			socket.Connect(new IPEndPoint(IPAddress.Loopback, 12345));

			byte[] datas = Encoding.UTF8.GetBytes(TestMessage + TestMessage + TestMessage + TestMessage + TestMessage);
			socket.Send(datas, datas.Length);
		}
	}
}