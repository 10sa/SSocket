using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SSocket.Enums;

namespace SSocket.Models
{
	public class SSocketPacket
	{
		public SSocket_PacketType PacketType { get; set; }
		public long DataSize { get; set; }

		private SSocketPacket() { }

		public SSocketPacket(SSocket_PacketType packetType, long dataSize)
		{
			PacketType = packetType;
			DataSize = dataSize;
		}

		public static SSocketPacket Parse(byte[] data)
		{
			try
			{
				SSocket_PacketType packetType = (SSocket_PacketType)Enum.Parse(typeof(SSocket_PacketType), BitConverter.ToInt32(data, 0).ToString());
				long dataSize = BitConverter.ToInt64(data, sizeof(int));

				return new SSocketPacket(packetType, dataSize);
			}
			catch (Exception) {
				throw;
			}
		}

		public byte[] GetBytes()
		{
			byte[] packetType = BitConverter.GetBytes((int)PacketType);
			byte[] dataSize = BitConverter.GetBytes(DataSize);

			return packetType.Concat(dataSize).ToArray();
		}

		public static int GetPacketSize()
		{
			return sizeof(int) + sizeof(long);
		}
	}
}
