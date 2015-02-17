using System;
using System.Security.Cryptography;

namespace dfk.crypto
{
    public static class HashByteExtentions
    {
        public static byte[] HashWith<T>(this byte[] bytesToHash) where T : HashAlgorithm, new()
        {
            if (bytesToHash.IsNullOrEmpty())
            {
                throw new ArgumentNullException("bytesToHash");
            }

            using (var hashAlgo = new T())
            {
                return hashAlgo.ComputeHash(bytesToHash);
            }
        }
    }
}
