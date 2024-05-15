using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace whatsappSmsTokenGen
{
    public class TokenGenerator
    {
        private byte[] _KEY;
        private byte[] _SIGNATURE;
        private byte[] _MD5_CLASSES;

        public TokenGenerator(string key, string signature, string md5Classes)
        {
            _KEY = Convert.FromBase64String(key);
            _SIGNATURE = Convert.FromBase64String(signature);
            _MD5_CLASSES = Convert.FromBase64String(md5Classes);
        }

        public string GetToken(string phoneNumber)
        {
            /*
            byte[] keyDecoded = Convert.FromBase64String(_KEY);
            byte[] sigDecoded = Convert.FromBase64String(_SIGNATURE);
            byte[] clsDecoded = Convert.FromBase64String(_MD5_CLASSES);
            byte[] data = Combine(sigDecoded, clsDecoded, Encoding.UTF8.GetBytes(phoneNumber));
            */

            byte[] data = _SIGNATURE.Concat(_MD5_CLASSES).Concat(Encoding.UTF8.GetBytes(phoneNumber)).ToArray();

            byte[] opad = new byte[64];
            byte[] ipad = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                opad[i] = (byte)(0x5C ^ _KEY[i]);
                ipad[i] = (byte)(0x36 ^ _KEY[i]);
            }

            using (SHA1 sha1 = new SHA1Managed())
            {
                byte[] subHash = sha1.ComputeHash(ipad.Concat(data).ToArray());
                byte[] hash = sha1.ComputeHash(opad.Concat(subHash).ToArray());
                string result = Convert.ToBase64String(hash);
                return result;
            }
        }
    }
}
