using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Web;
using System.Xml;
using System.IO;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Claims;
using System.ServiceModel;

namespace StsClient.Services
{
    public class LoginService
    {
        public bool ValidateUser(string userId, string password, out SessionSecurityToken sessionToken)
        {
            // authenticate with WS-Trust endpoint
            var factory = new WSTrustChannelFactory(
                new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential),
                new EndpointAddress("https://localhost/ActiveSTS/SecurityTokenService.svc"));

            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UserName.UserName = userId;
            factory.Credentials.UserName.Password = password;

            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointAddress("https://localhost/stsclient/"),
                KeyType = KeyTypes.Bearer,
                TokenType = Microsoft.IdentityModel.Tokens.SecurityTokenTypes.Saml11TokenProfile11,
            };

            var channel = factory.CreateChannel();

            var genericToken = channel.Issue(rst) as System.IdentityModel.Tokens.GenericXmlSecurityToken;

            // parse token
            var handlers = FederatedAuthentication.ServiceConfiguration.SecurityTokenHandlers;
            var token = handlers.ReadToken(new XmlTextReader(new StringReader(genericToken.TokenXml.OuterXml)));
            var identity = handlers.ValidateToken(token).First();

            // create session token
            sessionToken = new SessionSecurityToken(ClaimsPrincipal.CreateFromIdentity(identity));
            return true;
        }

    }
}