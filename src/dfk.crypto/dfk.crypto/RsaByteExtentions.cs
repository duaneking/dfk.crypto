using System;
using System.Security.Cryptography;

namespace dfk.crypto
{
    public static class RsaByteExtentions
    {
        /// <summary>
        /// RSA has a max valid size for the block of data it can encrypt at a time.
        /// 
        /// This value is dynamic based on the key Modulus size in bits, and the type of padding being done.
        /// 
        /// Any sized amount of data over this value and encryption will fail due to a block size that is too large.
        /// 
        /// To encypte large aounts of data seperate them into blocks equal to the size desired.
        /// </summary>
        /// <param name="bytes">The bytes to encrypt.</param>
        /// <param name="bits">The rsa key size in bytes.</param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns></returns>
        public static bool IsValidRsaEncryptionBlock(this byte[] bytes, int bits, bool doOaepPadding = false)
        {
            if (bytes.IsNullOrEmpty())
            {
                return false;
            }

            return bits.MaxRsaEncryptableBlockSizeInBytes(doOaepPadding) >= bytes.Length;
        }

        public static int MaxRsaEncryptableBlockSizeInBytes(this int sizeOfRsaKeyInBits, bool doOaepPadding = false)
        {
            return ((sizeOfRsaKeyInBits - 384)/8) + (doOaepPadding ? 7 : 37);
        }

        /// <summary>
        /// Check if a byte[] is empty or null.
        /// 
        /// Could be generic but I dont need that feature right now.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>True if empty, false otherwise.</returns>
        public static bool IsNullOrEmpty(this byte[] bytes)
        {
            return bytes == null || bytes.Length == 0;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="pubRsaKey"></param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns>An empty array of bytes on failure.</returns>
        public static byte[] EncryptWithRsa(this byte[] bytes, RSAParameters pubRsaKey, bool doOaepPadding = false)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            if (bytes.Length == 0)
            {
                throw new ArgumentOutOfRangeException("bytes", bytes, "byte[] bytes must be non-empty byte array.");
            }

            if (!pubRsaKey.IsSetToValidRsaKey(false))
            {
                throw new ArgumentOutOfRangeException("pubRsaKey", pubRsaKey, "Argument must be a valid RSA public key.  Do not pass a private key. This limitaiton is enforced for your safety so that you pay greater attention to the storage of private verses public keys.");
            }

            int bits = pubRsaKey.Modulus.Length * 8;

            if (!bytes.IsValidRsaEncryptionBlock(bits, doOaepPadding))
            {
                throw new ArgumentOutOfRangeException("bytes", bytes, string.Format("The byte[] must be a valid block size or encryption will fail. Your max valid data block size is {0} for a RSA key of {1} bits and doOaepPadding = {2}, yet your block of data is {3} bytes.", bits.MaxRsaEncryptableBlockSizeInBytes(doOaepPadding), bits, doOaepPadding, bytes.Length));
            }

            byte[] encryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(pubRsaKey);

                encryptedData = rsa.Encrypt(bytes, doOaepPadding);
            }

            return encryptedData;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="privRsaKey"></param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns></returns>
        public static byte[] DecryptWithRsa(this byte[] bytes, RSAParameters privRsaKey, bool doOaepPadding = false)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            if (bytes.Length == 0)
            {
                throw new ArgumentOutOfRangeException("bytes", bytes, "byte[] bytes must be non-empty.");
            }

            if (!privRsaKey.IsSetToValidRsaKey(true))
            {
                throw new ArgumentOutOfRangeException("privRsaKey", privRsaKey, "Argument must be a valid RSA private key key.  You may have passed a public key. Check your code and try again.");
            }

            byte[] decryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privRsaKey);

                decryptedData = rsa.Decrypt(bytes, doOaepPadding);
            }
            return decryptedData;
        }
    }
}
