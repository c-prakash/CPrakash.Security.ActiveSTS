using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Security;
using StsClient.Models;
using Microsoft.IdentityModel.Web;
using Microsoft.IdentityModel.Tokens;
using System.Threading;

namespace StsClient.Controllers
{
    public class AccountController : Controller
    {

        //
        // GET: /Account/LogOn

        public ActionResult LogOn()
        {
            return View();
        }

        //
        // POST: /Account/LogOn

        [HttpPost]
        public ActionResult LogOn(LogOnModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                SessionSecurityToken sessionToken;
                if (new StsClient.Services.LoginService().ValidateUser(model.UserName, model.Password, out sessionToken))
                {
                    FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);
                    Thread.CurrentPrincipal = sessionToken.ClaimsPrincipal;
                    if (Url.IsLocalUrl(returnUrl) && returnUrl.Length > 1 && returnUrl.StartsWith("/")
                        && !returnUrl.StartsWith("//") && !returnUrl.StartsWith("/\\"))
                    {
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "The user name or password provided is incorrect.");
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/LogOff

        public ActionResult LogOff()
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();

            return RedirectToAction("Index", "Home");
        }
    }
}
