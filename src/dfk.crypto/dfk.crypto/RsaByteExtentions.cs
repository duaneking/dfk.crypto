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
        /// <param name="bytesToEncrypt">The bytes to encrypt.</param>
        /// <param name="bitSizeOfRsaKey">The rsa key size in bytes.</param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns></returns>
        public static bool IsValidRsaEncryptionBlock(this byte[] bytesToEncrypt, int bitSizeOfRsaKey, bool doOaepPadding = false)
        {
            if (bytesToEncrypt.IsNullOrEmpty())
            {
                return false;
            }

            return bitSizeOfRsaKey.MaxRsaEncryptableBlockSizeInBytes(doOaepPadding) >= bytesToEncrypt.Length;
        }

        /// <summary>
        /// Calculate the max allowed encryptable block size based on the RSA key size and the padding type used.
        /// </summary>
        /// <param name="sizeOfRsaKeyInBits">The size of the RSA key in BITS.</param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns></returns>
        public static int MaxRsaEncryptableBlockSizeInBytes(this int sizeOfRsaKeyInBits, bool doOaepPadding = false)
        {
            return ((sizeOfRsaKeyInBits - 384)/8) + (doOaepPadding ? 7 : 37);
        }

        /// <summary>
        /// Encrypt with RSA using a Public Key.
        /// </summary>
        /// <param name="bytesToEncrypt">The bytes to encrypt.</param>
        /// <param name="publicRsaKey">The public RSA Key to use to encrypt.</param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns>An empty array of bytes on failure.</returns>
        public static byte[] EncryptWithRsa(this byte[] bytesToEncrypt, RSAParameters publicRsaKey, bool doOaepPadding = false)
        {
            if (bytesToEncrypt == null)
            {
                throw new ArgumentNullException("bytesToEncrypt");
            }

            if (bytesToEncrypt.Length == 0)
            {
                throw new ArgumentOutOfRangeException("bytesToEncrypt", bytesToEncrypt, "byte[] bytes must be non-empty byte array.");
            }

            if (!publicRsaKey.IsSetToValidRsaKey(false))
            {
                throw new ArgumentOutOfRangeException("publicRsaKey", publicRsaKey, "Argument must be a valid RSA public key.  Do not pass a private key. This limitaiton is enforced for your safety so that you pay greater attention to the storage of private verses public keys.");
            }

            int bits = publicRsaKey.Modulus.Length * 8;

            if (!bytesToEncrypt.IsValidRsaEncryptionBlock(bits, doOaepPadding))
            {
                throw new ArgumentOutOfRangeException("bytesToEncrypt", bytesToEncrypt, string.Format("The byte[] must be a valid block size or encryption will fail. Your max valid data block size is {0} for a RSA key of {1} bits and doOaepPadding = {2}, yet your block of data is {3} bytes.", bits.MaxRsaEncryptableBlockSizeInBytes(doOaepPadding), bits, doOaepPadding, bytesToEncrypt.Length));
            }

            byte[] encryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicRsaKey);

                encryptedData = rsa.Encrypt(bytesToEncrypt, doOaepPadding);
            }

            return encryptedData;
        }

        /// <summary>
        /// Decrypt data with a private key.
        /// </summary>
        /// <param name="bytesToDecrypt">The bytes to decrypt.</param>
        /// <param name="privateRsaKey">The private RSA key to use to decrypt.</param>
        /// <param name="doOaepPadding">True if you want to use OAEP pading as part of the calculation instead of PKCS#1 /"v1.5" padding.  Its not very well supported in .Net but it is in Mono</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] DecryptWithRsa(this byte[] bytesToDecrypt, RSAParameters privateRsaKey, bool doOaepPadding = false)
        {
            if (bytesToDecrypt == null)
            {
                throw new ArgumentNullException("bytesToDecrypt");
            }

            if (bytesToDecrypt.Length == 0)
            {
                throw new ArgumentOutOfRangeException("bytesToDecrypt", bytesToDecrypt, "byte[] bytes must be non-empty.");
            }

            if (!privateRsaKey.IsSetToValidRsaKey(true))
            {
                throw new ArgumentOutOfRangeException("privateRsaKey", privateRsaKey, "Argument must be a valid RSA private key key.  You may have passed a public key. Check your code and try again.");
            }

            byte[] decryptedData;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateRsaKey);

                decryptedData = rsa.Decrypt(bytesToDecrypt, doOaepPadding);
            }
            return decryptedData;
        }
    }
}
