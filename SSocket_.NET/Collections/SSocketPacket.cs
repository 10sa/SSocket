using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using SSocket.Models;
using SSocket.Enums;

namespace SSocket.Collections
{
	public class SSocketPacket
	{
		SSocketPacketModel packet;
		protected SSocketPacket() { }

		private SSocketPacket(SSocketPacketModel packet)
		{
			this.packet = packet;
		}

		public SSocketPacket(SSocket_PacketType packetType, long dataSize, long extraDataBit = 0)
		{
			packet = new SSocketPacketModel();
			packet.PacketType = packetType;
			packet.DataSize = dataSize;
			packet.ExtraDataBit = extraDataBit;
		}

		public static SSocketPacket Parse(byte[] data)
		{
			if (data.Length == GetPacketSize())
			{
				IntPtr classPtr = Marshal.AllocHGlobal(GetPacketSize());
				Marshal.Copy(data, 0, classPtr, data.Length);

				SSocketPacketModel packet = (SSocketPacketModel)Marshal.PtrToStructure(classPtr, typeof(SSocketPacketModel));
				Marshal.FreeHGlobal(classPtr);

				return new SSocketPacket(packet);
			}
			else
				throw new ArgumentException("data length mismatched.");
		}

		public SSocket_PacketType GetPacketType()
		{
			return packet.PacketType;
		}

		public long GetPacketDataSize()
		{
			return packet.DataSize;
		}

		public long GetPacketExtraDataBit()
		{
			return packet.ExtraDataBit;
		}

		public byte[] GetBytes()
		{
			int packetSize = GetPacketSize();
			byte[] bytes = new byte[packetSize];

			IntPtr classPtr = Marshal.AllocHGlobal(packetSize);
			Marshal.StructureToPtr(packet, classPtr, true);
			Marshal.Copy(classPtr, bytes, 0, bytes.Length);
			Marshal.FreeHGlobal(classPtr);

			return bytes;
		}

		public static int GetPacketSize()
		{
			return Marshal.SizeOf(typeof(SSocketPacketModel));
		}
	}
}
