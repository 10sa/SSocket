using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
