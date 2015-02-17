using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    [TestFixture]
    public class HashAlgorithmTests
    {
        private IEnumerable<HashAlgorithm> GetHashAlgorithmTestData()
        {
            yield return new SHA512Managed();
            yield return new SHA384Managed();
            yield return new SHA256Managed();
            yield return new SHA1Managed(); // Not secure. Do not use.
            yield return new RIPEMD160Managed();
        }

        [Test, TestCaseSource("GetHashAlgorithmTestData")]
        public void HashCanCompute<T>(T hash) where T : HashAlgorithm, new()
        {
            byte[] computeThisData = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xff };

            using (hash)
            {
                byte[] hashed = computeThisData.HashWith<T>();

                hashed.Should().NotBeNullOrEmpty();

                hashed.Length.Should().Be(hash.HashSize / 8);
            }
        }

        [ExpectedException(typeof(ArgumentNullException))]
        [Test, TestCaseSource("GetHashAlgorithmTestData")]
        public void NullBytesThrowsArgumentNullException<T>(T hash) where T : HashAlgorithm, new()
        {
            byte[] computeThisData = null;

            using (hash) { }

            // ReSharper disable once ExpressionIsAlwaysNull
            computeThisData.HashWith<T>();
        }

        [ExpectedException(typeof(ArgumentNullException))]
        [Test, TestCaseSource("GetHashAlgorithmTestData")]
        public void EmptyBytesThrowsArgumentNullException<T>(T hash) where T : HashAlgorithm, new()
        {
            byte[] computeThisData = new byte[0];

            using (hash) { }

            // ReSharper disable once ExpressionIsAlwaysNull
            computeThisData.HashWith<T>();
        }

    }
}
