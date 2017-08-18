namespace SSocket.Enums
{
	/// <summary>
	/// The reserved EBD enumeration of the SSocket protocol.
	/// </summary>
	public enum SSocketExtraDataBit : long
	{
		/// <summary>
		/// Start segmentation data send.
		/// </summary>
		StartSegmentation	= 1,

		/// <summary>
		/// Packet is segmentation data packet.
		/// </summary>
		SegmentPacket		= 1 << 1
	}
}
