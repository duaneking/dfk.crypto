using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    [TestFixture]
    public class RsaParametersTests
    {
        [Test]
        [TestCase(1024*1)]
        [TestCase(1024*2)]
        [TestCase(1024*4)]
        public void TestCanDetectPublicPrivateKeyRsaParametersANdTestEmpty(int bits)
        {
            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();
                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();
                privRsaKey.IsSetToValidRsaKey(false).Should().BeFalse();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();
                pubRsaKey.IsSetToValidRsaKey(false).Should().BeTrue();
                pubRsaKey.IsSetToValidRsaKey(true).Should().BeFalse();
            }
        }

        [Test]
        [TestCase(1024 * 1)]
        [TestCase(1024 * 2)]
        [TestCase(1024 * 4)]
        public void TestCanSerializeDeserializeRsaParameters(int bits)
        {
            using (var csp = new RSACryptoServiceProvider(bits))
            {
                var privRsaKey = csp.ExportParameters(true);
                privRsaKey.Should().NotBeNull();
                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();
                privRsaKey.IsSetToValidRsaKey(false).Should().BeFalse();

                privRsaKey = privRsaKey.ToPublicKeyXmlString().ToRsaParametersAsPublicKeyFromXmlString();
                privRsaKey.IsSetToValidRsaKey(true).Should().BeTrue();
                privRsaKey.IsSetToValidRsaKey(false).Should().BeFalse();

                var pubRsaKey = csp.ExportParameters(false);
                pubRsaKey.Should().NotBeNull();
                pubRsaKey.IsSetToValidRsaKey(false).Should().BeTrue();
                pubRsaKey.IsSetToValidRsaKey(true).Should().BeFalse();

                pubRsaKey = pubRsaKey.ToPublicKeyXmlString().ToRsaParametersAsPublicKeyFromXmlString();
                pubRsaKey.IsSetToValidRsaKey(false).Should().BeTrue();
                pubRsaKey.IsSetToValidRsaKey(true).Should().BeFalse();
            }
        }

        [Test]
        public void EmptyRsaParametersTest()
        {
            RSAParameters rsaParameters = new RSAParameters();

            string rsaString = rsaParameters.ToPublicKeyXmlString();

            rsaString.Should().Be("<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<RSAParameters xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" />");

            RSAParameters rsaParametersAfter = rsaString.ToRsaParametersAsPublicKeyFromXmlString();

            rsaParametersAfter.Equals(rsaParameters).Should().BeTrue();
        }

        [Test]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EmptyRsaParametersStringTest()
        {
            string rsaParameters = null;

            // ReSharper disable once ExpressionIsAlwaysNull
            rsaParameters.ToRsaParametersAsPublicKeyFromXmlString();
        }

        private IEnumerable<RSAParameters> GetRSAParametersBadPrivateKeyTestData()
        {
            yield return new RSAParameters
            {
                Q = null,
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = null,
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = null,
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = null,
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = null
            };
        }

        private IEnumerable<RSAParameters> GetRsaParametersBadPublicKeyTestData()
        {
            yield return new RSAParameters
            {
                Q = null,
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = null,
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = null,
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = null,
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = null,
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = null,
                Modulus = new byte[1],
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = null,
                P = new byte[1]
            };

            yield return new RSAParameters
            {
                Q = new byte[1],
                D = new byte[1],
                DP = new byte[1],
                DQ = new byte[1],
                Exponent = new byte[1],
                InverseQ = new byte[1],
                Modulus = new byte[1],
                P = null
            };

            yield return new RSAParameters
            {
                Q = null,
                D = null,
                DP = null,
                DQ = null,
                Exponent = new byte[1],
                InverseQ = null,
                Modulus = new byte[0],
                P = null
            };

            yield return new RSAParameters
            {
                Q = null,
                D = null,
                DP = null,
                DQ = null,
                Exponent = new byte[0],
                InverseQ = null,
                Modulus = new byte[1],
                P = null
            };

            yield return new RSAParameters
            {
                Q = null,
                D = null,
                DP = null,
                DQ = null,
                Exponent = null,
                InverseQ = null,
                Modulus = null,
                P = null
            };

            yield return new RSAParameters
            {
                Q = new byte[0],
                D = new byte[0],
                DP = new byte[0],
                DQ = new byte[0],
                Exponent = new byte[0],
                InverseQ = new byte[0],
                Modulus = new byte[0],
                P = new byte[0]
            };
        }

        [Test, TestCaseSource("GetRSAParametersBadPrivateKeyTestData")]
        public void IsSetToRsaKeyRsaParametersReturnsFalse(RSAParameters rsaParameters)
        {
            rsaParameters.IsSetToValidRsaKey(true).Should().BeFalse();
        }

        [Test, TestCaseSource("GetRsaParametersBadPublicKeyTestData")]
        public void IsSetToRsaKeyRsaParametersBadPublicKeyReturnsFalse(RSAParameters rsaParameters)
        {
            rsaParameters.IsSetToValidRsaKey(false).Should().BeFalse();
        }
    }
}
