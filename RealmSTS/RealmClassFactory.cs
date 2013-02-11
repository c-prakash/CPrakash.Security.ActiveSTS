using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Protocols.WSTrust;
using System.ServiceModel;

namespace CPrakash.Security.ActiveSTS.RealmSTS
{
    /// <summary>
    /// Creates service instance to handle incoming request.
    /// </summary>
    public class RealmClassFactory : WSTrustServiceHostFactory
    {
        /// <summary>
        /// Overrides the base class method. Configures the appropriate IssuerNameRegistry on
        /// the ServiceHost created by the base class.
        /// </summary>
        /// <param name="constructorString">Custom parameter specified in the 'Service' attribute of the .svc files.</param>
        /// <param name="baseAddresses">Collection of base address of the service obtained from the hosting layer (IIS).</param>
        /// <returns>Instance of ServiceHostBase.</returns>
        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            try
            {
                ServiceHostBase serviceHost = base.CreateServiceHost(constructorString, baseAddresses);
                return serviceHost;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
