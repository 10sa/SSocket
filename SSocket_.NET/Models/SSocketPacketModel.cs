using System;
using System.Runtime.InteropServices;

using SSocket.Enums;

namespace SSocket.Models
{
	[StructLayout(LayoutKind.Sequential, Pack = 0)]
	struct SSocketPacketModel
	{
		[MarshalAs(UnmanagedType.I4)]
		public SSocket_PacketType PacketType;

		[MarshalAs(UnmanagedType.I8)]
		public long DataSize;

		[MarshalAs(UnmanagedType.I8)]
		public long ExtraDataBit;
	}
}
