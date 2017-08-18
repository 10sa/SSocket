namespace SSocket.Enums
{
	/// <summary>
	/// The reserved packet type enumeration of SSocket protocol.
	/// </summary>
	public enum SSocketPacketType : int
	{
		/// <summary>
		///  Server-client plaintext key exchange.
		/// </summary>
		ServerHello = 1,

		/// <summary>
		/// Client-server plaintext key exchange
		/// </summary>
		ClientHello = 2,

		/// <summary>
		/// Data transmission.
		/// </summary>
		Data = 3
	}
}
