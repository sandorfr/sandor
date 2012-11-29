using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace HardwareTokenValidationService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select Service1.svc or Service1.svc.cs at the Solution Explorer and start debugging.
    public class ValidationService : IValidationService
    {
        static Lazy<byte[]> trustedASHWIDRootPublicKey = new Lazy<byte[]>(() => Convert.FromBase64String("MIICCgKCAgEAqO/O7+wSi5KU7c+qpYGNT6StSuyl8NqoPbblYQGZzjojc1pYZ5/1tlv1T/mgm3UezFNiEDynpTo75iQi9BiWLvL82aWIxv1R8DHDvQHcRbb2QCu3RXtFT+3AtHxYRPmJ+2p1O23xLqw1oV96lM06bZi4uCnmM5guM4N6hreoChDyBzJj5DLtTasFDKHXckmsNSwucO3uEvwjsdxa32HpLETNrtsGVI9PwdYVcq5QiTmJ9ZWC3P9B64lvvOCfeV0kFvcdOKre2CSX9pdHdFsjOMidLqrRH84JXPG5n5I40hFoPsxdTs+Un9JCveLxS/GnqVx5Bfsl98FT99nETXkPik20MHGm6VHljuDIg8cx/JhG9qJ2/KaBbXaQjTIhHy0+aStPqux707lkwda7X/o4xEGmbVrDEYf7vDNwSiaL5kTdy7gw05t7Gg4DtFHgyr97PFeaoNhL/n422IH6Jb1+A/VZLPbXp23dEHd3Ca524oUzpn1xIPg6Tyq26kIp0NPGKUsFLOe4Ss/Su4IgMJuiTR94LNlUE9gqKGhRVqX3265ZDrnRMJeCBGalAjwl+t3tCcJgvBdsoVq2l8yKE1b2tK7fz35AL0lB4GOOWCDMo08zO5vPPHJ+SEFCPWPjXud1bH/vbYAJpCukPt7kKywrqURWg762bmC5FhrhYulUnb8CAwEAAQ=="));

        public bool ValidateToken(byte[] token, byte[] nonce, byte[] certificate, byte[] signature)
        {
            SignedCms cms = new SignedCms();
            cms.Decode(certificate);

            var certificates = cms.Certificates.Cast<X509Certificate2>().ToArray();

            var leaf = certificates.Single(cert => cert.Extensions.Cast<X509Extension>().Any(usage =>
            {
                var eku = usage as X509EnhancedKeyUsageExtension;
                if (eku != null)
                {
                    return eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.4.1.311.10.5.40");
                }
                return false;
            }));

            var signedData = nonce.Concat(token).ToArray();

            var publicKeyProvider = leaf.PublicKey.Key as System.Security.Cryptography.RSACryptoServiceProvider;

            return publicKeyProvider.VerifyData(signedData, CryptoConfig.MapNameToOID("SHA1"), signature);

            // not working either (same results)
            //
            //SHA1Managed hash = new SHA1Managed();
            //byte[] hashedData;
            //hashedData = hash.ComputeHash(signedData);

            //if (!publicKeyProvider.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA1"), signature))
            //    throw new Exception("Invalid or Corrupted HardwareToken");

        }
    }
}
