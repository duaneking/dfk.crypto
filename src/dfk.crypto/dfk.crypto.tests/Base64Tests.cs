using FluentAssertions;
using NUnit.Framework;

namespace dfk.crypto.tests
{
    [TestFixture]
    public class Base64Tests
    {
        [TestCase("SGlyZSBNZS4=")]
        [TestCase("Q29weXJpZ2h0IDIwMTUgRHVhbmUgS2luZw==")]
        [TestCase("UGxlYXNlIGRvIG5vdCBzdGVhbC4=")]
        public void IsBase64Test(string text)
        {
            text.IsNoneEmptyBase64String().Should().BeTrue();
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase("    ")]
        [TestCase("  foo  ")]
        [TestCase("UGxlYXNlIGRvIG5vdCBzdGVhbC=")]
        [TestCase("UGxlYXNlIGRvIG5vdCBzdGVhbC= ")]
        [TestCase(" UGxlYXNlIGRvIG5vdCBzdGVhbC=")]
        [TestCase(" UGxlYXNlIGRvIG5vdCBzdGVhbC= ")]
        public void IsNotBase64Test(string text)
        {
            text.IsNoneEmptyBase64String().Should().BeFalse();
        }
    }
}
