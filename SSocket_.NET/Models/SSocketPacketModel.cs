using System;
using System.Runtime.InteropServices;

using SSocket.Enums;

namespace SSocket.Models
{
	[StructLayout(LayoutKind.Sequential, Pack =1)]
	struct SSocketPacketModel
	{
		[MarshalAs(UnmanagedType.I4)]
		public SSocketPacketType PacketType;

		[MarshalAs(UnmanagedType.I8)]
		public long DataSize;

		[MarshalAs(UnmanagedType.I8)]
		public long ExtraDataBit;
	}
}
