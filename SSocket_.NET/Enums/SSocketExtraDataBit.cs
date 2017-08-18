using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSocket.Enums
{
	public enum SSocketExtraDataBit : long
	{
		StartSegmentation	= 1,
		SegmentPacket		= 1 << 1
	}
}
