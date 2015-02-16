using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace dfk.crypto
{
    public static class RsaParametersExtentions
    {
        private static readonly XmlSerializer XmlSerializer = new XmlSerializer(typeof(RSAParameters));

        /// <summary>
        /// As a struct value type RSAParameters cannot be null.. but its fields can be.
        /// 
        /// This method checks if a RSAParameters is a valid public or private key as expected based on the set field values.
        /// 
        /// Public Keys only have the Modulus and Exponent set.
        /// 
        /// Private Keys have all fields set.
        /// </summary>
        /// <param name="rsaParameters">The RSAParameters to check.</param>
        /// <param name="isSetToRsaPrivateKey">True if we expect this to be a private RSAw key, false if not.</param>
        /// <returns>True if the RSAParameters object is a valid key of the desired privacy.</returns>
        public static bool IsSetToValidRsaKey(this RSAParameters rsaParameters, bool isSetToRsaPrivateKey)
        {
            if (isSetToRsaPrivateKey)
            {
                if (rsaParameters.D.IsNullOrEmpty())
                {
                    return false;
                }

                if (rsaParameters.DP.IsNullOrEmpty())
                {
                    return false;
                }

                if (rsaParameters.DQ.IsNullOrEmpty())
                {
                    return false;
                }

                if (rsaParameters.InverseQ.IsNullOrEmpty())
                {
                    return false;
                }

                if (rsaParameters.P.IsNullOrEmpty())
                {
                    return false;
                }

                if (rsaParameters.Q.IsNullOrEmpty())
                {
                    return false;
                }
            }
            else
            {
                if (!rsaParameters.D.IsNullOrEmpty())
                {
                    return false;
                }

                if (!rsaParameters.DP.IsNullOrEmpty())
                {
                    return false;
                }

                if (!rsaParameters.DQ.IsNullOrEmpty())
                {
                    return false;
                }

                if (!rsaParameters.InverseQ.IsNullOrEmpty())
                {
                    return false;
                }

                if (!rsaParameters.P.IsNullOrEmpty())
                {
                    return false;
                }

                if (!rsaParameters.Q.IsNullOrEmpty())
                {
                    return false;
                }
            }

            if (rsaParameters.Exponent.IsNullOrEmpty())
            {
                return false;
            }

            return !rsaParameters.Modulus.IsNullOrEmpty();
        }
 
        /// <summary>
        /// Convert a RSAParameters to a XML string represenbting the public key data it contains.
        /// 
        /// The type is set by .NET to not seialize the private key data.
        /// </summary>
        /// <param name="rsaParameter"></param>
        /// <returns></returns>
        public static string ToPublicKeyXmlString(this RSAParameters rsaParameter)
        {
            using (var stringWriter = new StringWriter())
            {
                XmlSerializer.Serialize(stringWriter, rsaParameter);

                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// Convert a string into a RSAParameters object representing a public key.
        /// </summary>
        /// <param name="xml"></param>
        /// <returns></returns>
        public static RSAParameters ToRsaParametersAsPublicKeyFromXmlString(this string xml)
        {
            if (string.IsNullOrWhiteSpace(xml))
            {
                throw new ArgumentNullException("xml");
            }

            using (var sr = new StringReader(xml))
            {
                return (RSAParameters)XmlSerializer.Deserialize(sr);
            }
        }
    }
}
