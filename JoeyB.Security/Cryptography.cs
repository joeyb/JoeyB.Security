using System;
using System.Security.Cryptography;
using System.Text;

namespace JoeyB.Security
{
    public static class Cryptography
    {
        #region Constants

        private const int DefaultHashIterations = 1000;
        private const int SaltSize = 16;

        #endregion

        #region Fields

        /// <summary>
        /// Source for crypto-grade random numbers.
        /// 
        /// Should only be accessed through the Random() method for locking purposes.
        /// </summary>
        private static readonly RandomNumberGenerator RandomNumberGenerator = RandomNumberGenerator.Create();

        #endregion

        #region Methods

        /// <summary>
        /// Crypto-grade, thread-safe random number generator.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static byte[] Random(int bytes)
        {
            var output = new byte[bytes];

            lock (RandomNumberGenerator) RandomNumberGenerator.GetBytes(output);

            return output;
        }

        /// <summary>
        /// Generate a random salt.
        /// 
        /// The format for salts is [number of iterations in hex].[salt number] (without the brackets).
        /// </summary>
        /// <param name="explicitIterations"></param>
        /// <returns></returns>
        public static string GenerateSalt(int? explicitIterations = null)
        {
            if (explicitIterations.HasValue && explicitIterations.Value < DefaultHashIterations)
                throw new ArgumentOutOfRangeException("explicitIterations", explicitIterations.Value,
                                                      "Cannot be less than " + DefaultHashIterations);

            var bytes = Random(SaltSize);

            var iterations = (explicitIterations ?? DefaultHashIterations).ToString("X");

            return iterations + "." + Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Securely hash a string using the specified salt.
        /// 
        /// The salt is expected to be in the same format as returned by the GenerateSalt() method.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static string Hash(string value, string salt)
        {
            var i = salt.IndexOf('.');
            var iterations = int.Parse(salt.Substring(0, i), System.Globalization.NumberStyles.HexNumber);

            salt = salt.Substring(i + 1);

            using (var pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(value), Convert.FromBase64String(salt), iterations))
            {
                var key = pbkdf2.GetBytes(24);

                return Convert.ToBase64String(key);
            }
        }

        #endregion
    }
}
