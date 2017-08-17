using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSocket
{
	static class Utils
	{
		public static byte[] ConcatByteArrays(params byte[][] arrays)
		{
			long arraySize = 0;
			foreach (var array in arrays)
				arraySize += array.Length;

			long arrayPosition = 0;
			byte[] concatedArray = new byte[arraySize];
			foreach (var array in arrays)
				Array.Copy(concatedArray, arrayPosition, array, 0, array.Length);

			return concatedArray;
		}
	}
}
