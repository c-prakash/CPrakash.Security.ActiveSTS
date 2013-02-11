using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols.WSTrust;

namespace CPrakash.Security.ActiveSTS.RealmSTS
{
    /// <summary>
    /// Application configuration for the Realm SecurityTokenService.
    /// </summary>
    public static class RealmSTSServiceConfig
    {
        // Issuer name placed into issued tokens
        internal const string StsName = "Realm STS";

        // Statics for location of certs
        internal static StoreName CertStoreName =(StoreName) Enum.ToObject(typeof(StoreName), 5);
        internal static StoreLocation CertStoreLocation = StoreLocation.LocalMachine;

        // Statics initialized from app.config
        internal static string CertDistinguishedName;
        internal static string TargetDistinguishedName;
        internal static string IssuerAddress;
        internal static string ExpectedAppliesToURI;

        #region Helper functions to load app settings from config
        /// <summary>
        /// Helper function to load Application Settings from config
        /// </summary>
        public static void LoadAppSettings()
        {
            CertDistinguishedName = ConfigurationManager.AppSettings["certDistinguishedName"];
            CheckNull(CertDistinguishedName);

            TargetDistinguishedName = ConfigurationManager.AppSettings["targetDistinguishedName"];
            CheckNull(TargetDistinguishedName);

            IssuerAddress = ConfigurationManager.AppSettings["issuerAddress"];
            CheckNull(IssuerAddress);

            ExpectedAppliesToURI = ConfigurationManager.AppSettings["expectedAppliestoURI"];
            CheckNull(ExpectedAppliesToURI);
        }

        /// <summary>
        /// Helper function to check if a required Application Setting has been specified in config.
        /// Throw if some Application Setting has not been specified.
        /// </summary>
        private static void CheckNull(string s)
        {
            if (String.IsNullOrEmpty(s))
            {
                throw new ConfigurationErrorsException("Required Configuration Element(s) missing at RealmSTS. Please check the STS configuration file.");
            }
        }

        #endregion

        #region constructors

        static RealmSTSServiceConfig()
        {
            LoadAppSettings();
        }

        #endregion
    }
}
