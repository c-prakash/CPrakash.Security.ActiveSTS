using Lagash.Xacml.Core;
using Lagash.Xacml.Core.Context;
using Lagash.Xacml.Core.Policy;
using Lagash.Xacml.Core.Runtime;
using Microsoft.IdentityModel.Claims;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Web;

namespace StsClient.Authorization
{
    public class CustomAuthorizationManager : ClaimsAuthorizationManager
    {
        public CustomAuthorizationManager()
        {
        }

        public override bool CheckAccess(AuthorizationContext context)
        {
            if (!context.Principal.Identity.IsAuthenticated)
                return true;

            FileStream policyStream = null;
            FileStream requestSteam = null;
            try
            {
                string requestFileName = "~/Xacml/AccessLinkOne Request.xml";
                var rc = context.Resource.FirstOrDefault();
                if (rc.Value.ToLower() == "http://localhost/StsClient/home/AccessLinkTwo".ToLower())
                    requestFileName = "~/Xacml/AccessLinkTwo Request.xml";

                policyStream = File.Open(HttpContext.Current.Server.MapPath("~/Xacml/1.IIA001Policy.xml"), FileMode.Open, FileAccess.Read, FileShare.Read);
                requestSteam = File.Open(HttpContext.Current.Server.MapPath(requestFileName), FileMode.Open, FileAccess.Read, FileShare.Read);

                var r = new EvaluationEngine().Evaluate((PolicyDocument)PolicyLoader.LoadPolicyDocument(policyStream), (ContextDocument) ContextLoader.LoadContextDocument(requestSteam));

                if (r != null && r.Results != null && r.Results.Count > 0)
                    return r.Results[0].Decision == Decision.Permit;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
            finally
            {
                if(policyStream!=null) policyStream.Close();
                policyStream = null;

                if(requestSteam!=null) requestSteam.Close();
                requestSteam = null;
            }

            return base.CheckAccess(context);
        }
    }
}