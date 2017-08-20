using System;
using System.Runtime.InteropServices;
using SSocketLib.Models;
using SSocketLib.Enums;

namespace SSocketLib.Collections
{
	/// <summary>
	/// A collection that implements SSocket protocol packets.
	/// </summary>
	public class SSocketPacket
	{
		private SSocketPacketModel packet;
		protected SSocketPacket() { }

		private SSocketPacket(SSocketPacketModel packet)
		{
			this.packet = packet;
		}

		/// <summary>
		/// Create new SSocketPacket instance.
		/// </summary>
		/// <param name="packetType">Packet type to send.</param>
		/// <param name="dataSize">Size of data to send.</param>
		/// <param name="extraDataBit">EDB to send.</param>
		public SSocketPacket(SSocketPacketType packetType, long dataSize, long extraDataBit = 0)
		{
			SetPacketData(packetType, dataSize, extraDataBit);
		}

		/// <summary>
		/// Create new SSocketPacket instance.
		/// </summary>
		/// <param name="packetType">Packet type to send.</param>
		/// <param name="dataSize">Size of data to send.</param>
		/// <param name="extraDataBit">EDB to send.</param>
		public SSocketPacket(long packetType, long dataSize, long extraDataBit = 0)
		{
			SetPacketData((SSocketPacketType)Enum.Parse(typeof(SSocketPacketType), packetType.ToString()), dataSize, extraDataBit);
		}

		/// <summary>
		/// Parse from byte array to SSocketPacket.
		/// </summary>
		/// <param name="data">Byte Data to parse</param>
		/// <returns></returns>
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

		/// <summary>
		/// Get Setted Packet of type.
		/// </summary>
		/// <returns>Setted packet of type.</returns>
		public SSocketPacketType GetPacketType()
		{
			return packet.PacketType;
		}

		/// <summary>
		/// Get Setted Packet of Data Size.
		/// </summary>
		/// <returns>Setted packet of data size.</returns>
		public long GetPacketDataSize()
		{
			return packet.DataSize;
		}

		/// <summary>
		/// Get Setted Packet of EDB.
		/// </summary>
		/// <returns>Setted Packet of EDB.</returns>
		public long GetPacketExtraDataBit()
		{
			return packet.ExtraDataBit;
		}

		/// <summary>
		///  Gets binary bytes of packet.
		/// </summary>
		/// <returns>Binary bytes of packet.</returns>
		public byte[] GetBytes()
		{
			return Utils.StructureToBytes(packet);
		}

		/// <summary>
		/// Get packet of binary size.
		/// </summary>
		/// <returns>Binary size of packet.</returns>
		public static int GetPacketSize()
		{
			return Marshal.SizeOf(typeof(SSocketPacketModel));
		}

		/// <summary>
		/// Returns whether the EDB has a specific value.
		/// </summary>
		/// <param name="edb">Specific EDB value.</param>
		/// <returns>if has specific EDB value, Otherwise return false.</returns>
		public bool HasExtraDataBit(SSocketExtraDataBit edb)
		{
			return (packet.ExtraDataBit & (long)edb) > 0 ? true : false;
		}

		/// <summary>
		/// Returns whether the EDB has a specific value.
		/// </summary>
		/// <param name="edb">Specific EDB value.</param>
		/// <returns>if has specific EDB value, Otherwise return false.</returns>
		public bool HasExtraDataBit(long edb)
		{
			return (packet.ExtraDataBit & edb) > 0 ? true : false;
		}

		private void SetPacketData(SSocketPacketType packetType, long dataSize, long extraDataBit)
		{
			packet = new SSocketPacketModel
			{
				PacketType = packetType,
				DataSize = dataSize,
				ExtraDataBit = extraDataBit
			};
		}
	}
}
