﻿
using System.Text.RegularExpressions;

namespace dfk.crypto
{
    public static class StringExtentions
    {
        /// <summary>
        /// Compile regex in memory. 
        /// 
        /// Takes longer to initialize but speeds up how it runs when called multiple times.
        /// </summary>
        private static readonly Regex Base64Regex = new Regex(@"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.Compiled);

        /// <summary>
        /// Check if a string is contains a base64 encoded string of binary data or not.
        /// </summary>
        /// <param name="text">The text to check.</param>
        /// <returns>True if the string is encoded in a valid base64 encoding containing data; false otherwise.</returns>
        public static bool IsNonEmptyBase64String(this string text)
        {
            if (text == null)
            {
                return false;
            }

            int oldLength = text.Length;

            text = text.Trim();

            if (text.Length == 0 || text.Length != oldLength)
            {
                return false;
            }

            return (text.Length % 4 == 0) && Base64Regex.IsMatch(text);
        }
    }
}
