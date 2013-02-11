using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.SecurityTokenService;
using CPrakash.Security.ActiveSTS.Common;

namespace CPrakash.Security.ActiveSTS.RealmSTS
{
    public class RealmSecurityTokenServiceConfiguration: SecurityTokenServiceConfiguration
    {
        public static X509SigningCredentials x509Cert = new X509SigningCredentials( X509Helper.GetX509Certificate2( RealmSTSServiceConfig.CertStoreName,
                                                                RealmSTSServiceConfig.CertStoreLocation,
                                                                RealmSTSServiceConfig.CertDistinguishedName ) );

        /// <summary>
        /// Creates an instance of RealmSecurityTokenServiceConfiguration.
        /// </summary>
        public RealmSecurityTokenServiceConfiguration()
            : base( RealmSTSServiceConfig.IssuerAddress, x509Cert )
        {
            SecurityTokenService = typeof( RealmSecurityTokenService );
        }
    }
}
