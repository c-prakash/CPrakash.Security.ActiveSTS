using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.WSIdentity;

namespace CPrakash.Security.ActiveSTS.RealmSTS
{
    public class CustomUserNameSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            UserNameSecurityToken unToken = token as UserNameSecurityToken;
            if (unToken == null)
            {
                throw new ArgumentException("token");
            }

            // replace with proper password validation!
            if (!(unToken.UserName == "demouser" && unToken.Password == "demouser"))
            {
                throw new SecurityTokenValidationException();
            }

            ClaimsIdentity id = new ClaimsIdentity(new List<Claim>
            {
                new Claim(WSIdentityConstants.ClaimTypes.Name, unToken.UserName)
            }, "UserName");

            var ids = new ClaimsIdentityCollection();
            ids.Add(id);

            return ids;
        }

        public override bool CanValidateToken
        {
            get
            {
                return true;
            }
        }
    }
}
