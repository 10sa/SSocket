namespace SSocket.Enums
{
	public enum SSocketPacketType : int
	{
		ServerHello		= 1,
		ClientHello		= 2,
		Data					= 3,
		Segmentation_Send = 4,
	}
}
