using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    /// <summary>
    /// Summary description for SymmetricAlgorithmCryptoTests
    /// </summary>
    [TestFixture]
    public class SymmetricAlgorithmCryptoTests
    {
        private IEnumerable<SymmetricAlgorithm> GetSymmetricAlgorithmTestData()
        {
            yield return new DESCryptoServiceProvider();
            yield return new RijndaelManaged();
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        public void SymmetricAlgorithmEncryptDecryptWillWork<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = Encoding.UTF8.GetBytes("secret data to encrypt with random iv and known key");

            using (algo)
            {
				algo.GenerateKey();
                algo.GenerateIV();

                // Encrypt the string to an array of bytes. 
                byte[] encrypted = original.EncryptBytesWith<T>(algo.Key, algo.IV);

                // Decrypt the bytes to a string. 
                byte[] roundtrip = encrypted.DecryptBytesWith<T>(algo.Key, algo.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original of size {0}:  {1}", original.Length, original.ToHexString());
                Console.WriteLine("encrypted of size {0}: {1}", encrypted.Length, encrypted.ToHexString());
                Console.WriteLine("Round Trip of size {0}: {1}", roundtrip.Length, roundtrip.ToHexString());

                roundtrip.Should().Equal(original);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptBytesEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[0];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.EncryptBytesWith<T>(algo.Key, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptBytesEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[0];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.DecryptBytesWith<T>(algo.Key, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptBytesNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = null;

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.DecryptBytesWith<T>(algo.Key, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptBytesNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = null;

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.EncryptBytesWith<T>(algo.Key, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptKeyEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.DecryptBytesWith<T>(new byte[0], algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptKeyNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.DecryptBytesWith<T>(null, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptIvEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.DecryptBytesWith<T>(algo.Key, new byte[0]);
            }
        }


        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmDecryptIvNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.DecryptBytesWith<T>(algo.Key, null);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SymetricAlgorithmDecryptKeyLengthNotValidSize<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.DecryptBytesWith<T>(new byte[algo.BlockSize], algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SymetricAlgorithmDecryptIvLengthNotBlockSizeInBits<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.DecryptBytesWith<T>(algo.Key, new byte[algo.BlockSize]);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptKeyEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.EncryptBytesWith<T>(new byte[0], algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptKeyNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.EncryptBytesWith<T>(null, algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptIvEmptyThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.EncryptBytesWith<T>(algo.Key, new byte[0]);
            }
        }


        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SymmetricAlgorithmEncryptIvNullThrowsArgumentNullException<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                // ReSharper disable once ExpressionIsAlwaysNull
                original.EncryptBytesWith<T>(algo.Key, null);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SymetricAlgorithmEncryptKeyLengthNotValidSize<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.EncryptBytesWith<T>(new byte[algo.BlockSize], algo.IV);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SymetricAlgorithmEncryptIvLengthNotBlockSizeInBits<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            byte[] original = new byte[algo.BlockSize / 8];

            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                original.EncryptBytesWith<T>(algo.Key, new byte[algo.BlockSize]);
            }
        }

        [Test, TestCaseSource("GetSymmetricAlgorithmTestData")]
        public void SymetricAlgorithmBlockSizeInBits<T>(T algo) where T : SymmetricAlgorithm, new()
        {
            using (algo)
            {
                algo.GenerateKey();
                algo.GenerateIV();

                var keySizes = algo.LegalKeySizesAsIntArray();

                keySizes.Should().NotBeNullOrEmpty();
                keySizes.Should().Contain(algo.KeySize);
            }
        }

        [Test]
        public void SymetricAlgorithmBlockSizeFromNull()
        {
            RijndaelManaged algo = null;

            // ReSharper disable once ExpressionIsAlwaysNull
            algo.LegalKeySizesAsIntArray().Should().BeEmpty();
        }
    }
}
