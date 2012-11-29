using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace HardwareTokenValidationService
{
    public static class ByteArrayHelpers
    {
        public static bool CompareTo(this byte[] reference, byte[] other)
        {
            if (reference.Length != other.Length)
                return false;
            else
            {
                for (int i = 0; i < reference.Length; i++)
                {
                    if (reference[i] != other[i])
                        return false;
                }
                return true;
            }
        }
    }
}