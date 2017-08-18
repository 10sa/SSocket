using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

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

		public static byte[] StructureToBytes(object structure)
		{
			int objectSize = Marshal.SizeOf(structure);
			IntPtr structurePtr = Marshal.AllocHGlobal(objectSize);
			byte[] bytes = new byte[objectSize];

			Marshal.StructureToPtr(structure, structurePtr, false);
			Marshal.Copy(structurePtr, bytes, 0, bytes.Length);
			Marshal.FreeHGlobal(structurePtr);

			return bytes;
		}
	}
}
