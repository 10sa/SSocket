using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSocket.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSocket.Collections.Tests
{
	[TestClass()]
	public class SSocketPacketTests
	{
		[TestMethod()]
		public void ParseTest()
		{
			SSocketPacket socketPacket = new SSocketPacket(Enums.SSocket_PacketType.Data, 22);
			byte[] socketPacketBytes = socketPacket.GetBytes();

			SSocketPacket sSocketPacket = SSocketPacket.Parse(socketPacketBytes);

			Assert.IsTrue(socketPacketBytes.SequenceEqual(sSocketPacket.GetBytes()));
		}
	}
}