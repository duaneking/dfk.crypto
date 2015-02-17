
using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    [TestFixture]
    public class BytesToHexStringTests
    {
        [Test]
        public void NullBytesArrayEqualsEmptyString()
        {
            byte[] bytes = null;

            // ReSharper disable once ExpressionIsAlwaysNull
            bytes.ToHexString().Should().Be(string.Empty);
        }

        [Test]
        public void EmptyBytesArrayEqualsEmptyString()
        {
            byte[] bytes = new byte[0];

            bytes.ToHexString().Should().Be(string.Empty);
        }

        [Test]
        public void BytesArrayEqualsCorrectStringNumbers()
        {
            byte[] bytes = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            bytes.ToHexString().Should().Be("01020304050607080910111213141516");
        }

        [Test]
        public void BytesArrayEqualsCorrectStringRanged()
        {
            byte[] bytes = { 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaf, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x00 };

            bytes.ToHexString().Should().Be("ff020304050607af0910111213141500");
        }
    }
}
