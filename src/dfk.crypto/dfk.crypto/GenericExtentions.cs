using System.Text;

namespace dfk.crypto
{
    public static class GenericExtentions
    {
        /// <summary>
        /// Check if a T[] is empty or null.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>True if empty, false otherwise.</returns>
        public static bool IsNullOrEmpty<T>(this T[] bytes)
        {
            return bytes == null || bytes.Length == 0;
        }

        public static string ToHexString(this byte[] bytes)
        {
            if (bytes.IsNullOrEmpty())
            {
                return string.Empty;
            }

            StringBuilder hex = new StringBuilder(bytes.Length * 2);

            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            return hex.ToString();
        }
    }
}
