using Microsoft.IdentityModel.Claims;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace StsClient.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = "Welcome to ASP.NET MVC!";

            return View();
        }

        public ActionResult About()
        {
            var claims = new List<string>();
            if (User.Identity != null && User.Identity.IsAuthenticated && User.Identity is ClaimsIdentity)
            {
                var claimsIdentity = User.Identity as ClaimsIdentity;
                foreach (var claim in claimsIdentity.Claims)
                    claims.Add(claim.ToString());
                    
            }
            return View(claims);
        }

        public ActionResult AccessLinkOne()
        {
            return Content("You are authorize to view this page");
        }

        public ActionResult AccessLinkTwo()
        {
            return Content("You are authorize to view this page");
        }
    }
}
