using System;
using System.Diagnostics;
using System.Security.Cryptography;
using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    [TestFixture]
    public class BytesTests
    {
        /// <summary>
        /// The padding used in PKCS#1 /"v1.5" padding uses 11 bytes.
        /// </summary>
        private const int PkcsOnePaddingBytesCount = 11;

        /// <summary>
        /// The padding used in OAEP padding uses 41 bytes.
        /// </summary>
        private const int OaepPaddingBytesCount = 41;

        /// <summary>
        /// Get non-cyptographicly random data for tests.
        /// 
        /// A choice made to make tests run faster; It ulti
        /// </summary>
        private static readonly Random Random = new Random();

        [Test]
        [TestCase(1024 * 1, 128 - PkcsOnePaddingBytesCount)]
        [TestCase(1024 * 2, 256 - PkcsOnePaddingBytesCount)]
        public void MaxRsaEncryptableBlockSizeEqualsExpectedTest(int bits, int maxAfterPadding)
        {
            int max = bits.MaxRsaEncryptableBlockSizeInBytes();

            (max == maxAfterPadding).Should().BeTrue(string.Format(" a max of {0} + {1} padding bytes should be {2} bytes max.", max, PkcsOnePaddingBytesCount, maxAfterPadding));
        }

        [Test]
        [TestCase(1024 * 1, 128 - OaepPaddingBytesCount)]
        [TestCase(1024 * 2, 256 - OaepPaddingBytesCount)]
        public void MaxRsaEncryptableBlockSizeEqualsExpectedWithOaepPaddingTest(int bits, int maxAfterPadding)
        {
            int max = bits.MaxRsaEncryptableBlockSizeInBytes(true);

            (max == maxAfterPadding).Should().BeTrue(string.Format(" a max of {0} + {1} padding bytes should be {2} bytes max.", max, OaepPaddingBytesCount, maxAfterPadding));
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        public void BytesTooLargeToEncryptTest(int bits)
        {
            byte[] bytes = new byte[bits.MaxRsaEncryptableBlockSizeInBytes() + 1];

            Debug.WriteLine("bytes.Length == " + bytes.Length);

            bytes.IsValidRsaEncryptionBlock(bits).Should().BeFalse();
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        public void NullBytesAreInvalidSizeForRsaTest(int bits)
        {
            byte[] bytes = null;

            // ReSharper disable once ExpressionIsAlwaysNull
            bytes.IsValidRsaEncryptionBlock(bits).Should().BeFalse();
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        public void EmptyBytesAreInvalidSizeForRsaTest(int bits)
        {
            byte[] bytes = new byte[0];

            bytes.IsValidRsaEncryptionBlock(bits).Should().BeFalse();
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        public void BytesSmallEnoughToEncryptTest(int bits)
        {
            byte[] bytes = new byte[bits.MaxRsaEncryptableBlockSizeInBytes()];

            bytes.IsValidRsaEncryptionBlock(bits).Should().BeTrue();
        }

        [Test]
        public void NullBytesShouldBeNullOrEmptyTest()
        {
            byte[] bytes = null;

            // ReSharper disable once ExpressionIsAlwaysNull
            bytes.IsNullOrEmpty().Should().BeTrue();
        }

        [Test]
        public void EmptyBytesShouldBeNullOrEmptyTest()
        {
            byte[] bytes = new byte[0];

            bytes.IsNullOrEmpty().Should().BeTrue();
        }

        [Test]
        public void NoneEmptyBytesShouldNotBeNullOrEmptyTest()
        {
            byte[] bytes = new byte[1];

            bytes.IsNullOrEmpty().Should().BeFalse();
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        public void TestCanEncryptAndDecrypt(int bits)
        {
            byte[] data = new byte[((bits - 384) / 8) + 37];

            Debug.WriteLine("Encrypting the max of {0} bytes with a {1} bit key.",  data.Length, bits);

            Random.NextBytes(data);

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                pubRsaKey.IsSetToValidRsaKey(false).Should().BeTrue();

                byte[] encrypted = data.EncryptWithRsa(pubRsaKey);

                encrypted.IsNullOrEmpty().Should().BeFalse();

                encrypted.Should().NotBeNullOrEmpty();
                encrypted.Should().NotEqual(data);

                byte[] decrypted = encrypted.DecryptWithRsa(privRsaKey);

                decrypted.IsNullOrEmpty().Should().BeFalse();

                decrypted.Should().NotBeNullOrEmpty();
                decrypted.Should().Equal(data);
            }
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentNullException))]
        public void NullBytesToEncryptThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = null;

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                // ReSharper disable once ExpressionIsAlwaysNull
                bytes.EncryptWithRsa(pubRsaKey);
            }
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void EmptyBytesToEncryptThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = new byte[0];

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                bytes.EncryptWithRsa(pubRsaKey);
            }
        }

        /// <summary>
        ///  use private key instead of public key intentionally.
        /// </summary>
        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void UseingPrivateKeyToEncryptThrowsArgumentOutOfRangeExceptionTest(int bits)
        {
            byte[] bytes = new byte[bits.MaxRsaEncryptableBlockSizeInBytes()];

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                bytes.EncryptWithRsa(privRsaKey);
            }
        }

        /// <summary>
        //  Use empty key instead of public key intentionally.
        /// </summary>
        /// <param name="bits">bits to test the key at</param>
        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void UseingEmptyKeyToEncryptThrowsArgumentOutOfRangeExceptionTest(int bits)
        {
            byte[] bytes = new byte[bits.MaxRsaEncryptableBlockSizeInBytes()];

            bytes.EncryptWithRsa(new RSAParameters());
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void UseTooManyBytesToEncryptThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = new byte[bits.MaxRsaEncryptableBlockSizeInBytes() + 1];

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                bytes.EncryptWithRsa(pubRsaKey);
            }
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentNullException))]
        public void NullBytesToDecryptThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = null;

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                // ReSharper disable once ExpressionIsAlwaysNull
                bytes.DecryptWithRsa(privRsaKey);
            }
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        [TestCase(1024 * 8)]
        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void EmptyBytesToDecryptThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = new byte[0];

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                bytes.DecryptWithRsa(privRsaKey);
            }
        }
        [Test]
        [TestCase(1024 * 1)]
//        [TestCase(1024 * 2)]
//        [TestCase(1024 * 4)]
//        [TestCase(1024 * 8)]
//        [TestCase(1024 * 16)]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void UsePublicKeyToDecryptInsteadOfPrivatekeyThrowsNullArgumentExceptionTest(int bits)
        {
            byte[] bytes = {0x13, 0x21, 0x73};

            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();

                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();

                pubRsaKey.IsSetToValidRsaKey(false).Should().BeTrue();

                bytes.DecryptWithRsa(pubRsaKey);
            }
        }
    }
}
