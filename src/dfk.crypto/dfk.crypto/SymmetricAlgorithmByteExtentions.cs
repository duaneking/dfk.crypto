using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace dfk.crypto
{
    public static class SymmetricAlgorithmByteExtentions
    {
        public static byte[] EncryptBytesWith<T>(this byte[] bytesToEncrypt, byte[] key, byte[] iv) where T : SymmetricAlgorithm, new()
        {
            if (bytesToEncrypt.IsNullOrEmpty())
            {
                throw new ArgumentNullException("bytesToEncrypt");
            }

            if (key.IsNullOrEmpty())
            {
                throw new ArgumentNullException("key");
            }

            if (iv.IsNullOrEmpty())
            {
                throw new ArgumentNullException("iv");
            }

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (var alg = new T())
            {
                if (!alg.ValidKeySize(key.Length*8))
                {
                    StringBuilder sb = new StringBuilder();

                    foreach (var keySize in alg.LegalKeySizesAsIntArray())
                    {
                        sb.AppendLine(String.Format("\t --> {0} bits", keySize));
                    }

                    throw new ArgumentOutOfRangeException("key", key, string.Concat("Key size of ", key.Length * 8, " bits is not in the allowed size range for selected algorithm.  Allowed Sizes include: ", Environment.NewLine , sb));
                }

                if (iv.Length != alg.BlockSize / 8)
                {
                    throw new ArgumentOutOfRangeException("iv", iv.ToHexString(), string.Format("The Initialization Vector (iv) is not the correct size.  Pass in an IV equal to the block size for the algorithm you are using."));
                }

                alg.Key = key;
                alg.IV = iv;

                using (ICryptoTransform encryptor = alg.CreateEncryptor(alg.Key, alg.IV))
                {
                    using (var stream = new MemoryStream())
                    {
                        using (var encrypt = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                        {
                            encrypt.Write(bytesToEncrypt, 0, bytesToEncrypt.Length);
                            encrypt.FlushFinalBlock();
                            return stream.ToArray();
                        }
                    }
                }
            }
        }

        public static byte[] DecryptBytesWith<T>(this byte[] bytesToEncrypt, byte[] key, byte[] iv) where T : SymmetricAlgorithm, new()
        {
            // Check arguments. 
            if (bytesToEncrypt.IsNullOrEmpty())
            {
                throw new ArgumentNullException("bytesToEncrypt");
            }

            if (key.IsNullOrEmpty())
            {
                throw new ArgumentNullException("key");
            }

            if (iv.IsNullOrEmpty())
            {
                throw new ArgumentNullException("iv");
            }

            using (T alg = new T())
            {
                if (!alg.ValidKeySize(key.Length * 8))
                {
                    StringBuilder sb = new StringBuilder();

                    foreach (var keySize in alg.LegalKeySizesAsIntArray())
                    {
                        sb.AppendLine(String.Format("\t --> {0} bits", keySize));
                    }

                    throw new ArgumentOutOfRangeException("key", key, string.Concat("Key size of ", key.Length * 8, " bits is not in the allowed size range for selected algorithm.  Allowed Sizes include: ", Environment.NewLine, sb));
                }

                if (iv.Length != alg.BlockSize / 8)
                {
                    throw new ArgumentOutOfRangeException("iv", iv.ToHexString(), string.Format("The Initialization Vector (iv) is not the correct size.  Pass in an IV equal to the block size for the algorithm you are using."));
                }

                alg.Key = key;
                alg.IV = iv;

                // Create a decrytor to perform the stream transform.
                using (ICryptoTransform decryptor = alg.CreateDecryptor(alg.Key, alg.IV))
                {
                    // Create the streams used for decryption. 
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var encrypt = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                        {
                            encrypt.Write(bytesToEncrypt, 0, bytesToEncrypt.Length);
                            encrypt.FlushFinalBlock();
                            return memoryStream.ToArray();
                        }
                    }
                }
            }
        }
    }
}
