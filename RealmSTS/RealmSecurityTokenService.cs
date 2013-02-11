using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.SecurityTokenService;
using CPrakash.Security.ActiveSTS.Common;

namespace CPrakash.Security.ActiveSTS.RealmSTS
{
    public class RealmSecurityTokenService: Microsoft.IdentityModel.SecurityTokenService.SecurityTokenService
    {
        /// <summary>
        /// The constructor.
        /// </summary>
        /// <param name="config">The <see cref="SecurityTokenServiceConfiguration"/> object to be 
        /// passed to the base class.</param>
        public RealmSecurityTokenService(SecurityTokenServiceConfiguration config)
            : base(config)
        {
        }

        /// <summary>
        /// Override this method to provide scope specific encrypting credentials.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        protected override Scope GetScope( IClaimsPrincipal principal, RequestSecurityToken request )
        {
            ValidateAppliesTo( request.AppliesTo );
            Scope scope = new Scope( request.AppliesTo.Uri.AbsoluteUri );
            scope.SigningCredentials = new X509SigningCredentials(X509Helper.GetX509Certificate2(RealmSTSServiceConfig.CertStoreName,
                                                                RealmSTSServiceConfig.CertStoreLocation,
                                                                RealmSTSServiceConfig.CertDistinguishedName));
            scope.EncryptingCredentials = new X509EncryptingCredentials(X509Helper.GetX509Certificate2(RealmSTSServiceConfig.CertStoreName,
                                                                RealmSTSServiceConfig.CertStoreLocation,
                                                                RealmSTSServiceConfig.TargetDistinguishedName));
            return scope;
        }

        /// <summary>
        /// This overriden method returns a collection of output subjects to be included in the issued token.
        /// </summary>
        /// <param name="scope">The scope information about the Relying Party.</param>
        /// <param name="principal">The IClaimsPrincipal that represents the identity of the requestor.</param>
        /// <param name="request">The token request parameters that arrived in the call.</param>
        /// <returns>The claims collection that will be placed inside the issued token.</returns>    
        protected override IClaimsIdentity GetOutputClaimsIdentity( IClaimsPrincipal principal, RequestSecurityToken request, Scope scope )
        {
            string clientName = ServiceSecurityContext.Current.PrimaryIdentity.Name;
            if (string.IsNullOrEmpty(clientName))
            {
                throw new FaultException("The client name was not specified.");
            }

            // Create Name
            List<Claim> claims = new List<Claim>();
            // Name claim
            Claim nameClaim = new Claim(ClaimTypes.Name, clientName);
            claims.Add(nameClaim);

            return new ClaimsIdentity(claims);
        }

        /// <summary>
        /// Validates the appliesTo and throws an exception if the appliesTo is null or appliesTo contains some unexpected address.  
        /// </summary>
        void ValidateAppliesTo(EndpointAddress appliesTo)
        {
            if (appliesTo == null)
            {
                throw new InvalidRequestException("The appliesTo is null.");
            }

            if (!appliesTo.Uri.Equals(new Uri(RealmSTSServiceConfig.ExpectedAppliesToURI)))
            {
                throw new InvalidRequestException(String.Format("The relying party address is not valid. Expected value is {0}, the actual value is {1}.", RealmSTSServiceConfig.ExpectedAppliesToURI, appliesTo.Uri.AbsoluteUri));
            }
        }
    }
}
