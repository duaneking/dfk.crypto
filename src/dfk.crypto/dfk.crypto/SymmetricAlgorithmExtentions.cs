using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace dfk.crypto
{
    public static class SymmetricAlgorithmExtentions
    {
        public static int[] LegalKeySizesAsIntArray(this SymmetricAlgorithm symmetricAlgorithm)
        {
            if (symmetricAlgorithm == null)
            {
                return new int[0];
            }

            List<int> legalKeySizes = new List<int>();

            KeySizes[] validSizes = symmetricAlgorithm.LegalKeySizes;

            foreach (var validSize in validSizes)
            {
                if (validSize.SkipSize == 0)
                {
                    // We assume that validSize.MinSize is equal to MazSize in this case as that is what .NET does with for example DES (Don't use DES).
                    legalKeySizes.Add(validSize.MinSize);
                }
                else
                {
                    for (int allowedKeySize = validSize.MinSize; allowedKeySize <= validSize.MaxSize; allowedKeySize += validSize.SkipSize)
                    {
                        legalKeySizes.Add(allowedKeySize);
                    }
                }
            }

            return legalKeySizes.Distinct().OrderByDescending( val => val ).ToArray();
        }
    }
}
