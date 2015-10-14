using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.SessionState;
using Sun.Identity.Saml2;
using Sun.Identity.Saml2.Exceptions;
using System.Xml;
using System.Web.Caching;
using System.Web.Configuration;

namespace gov.dhs.uscis.icam.fedlet
{
    class FederationHandler : IHttpHandler, IRequiresSessionState
    {
        public void ProcessRequest(HttpContext Context)
        {
            HttpRequest Request = Context.Request;
            HttpResponse Response = Context.Response;
            HttpSessionState Session = Context.Session;
            Cache Cache = Context.Cache;

            if (Request.Url.AbsoluteUri.EndsWith("acs.saml2"))
            {
                string errorMessage = null;
                string errorTrace = null;
                AuthnResponse authnResponse = null;
                ServiceProviderUtility serviceProviderUtility = null;

                try
                {
                    serviceProviderUtility = (ServiceProviderUtility)Cache["spu"];
                    if (serviceProviderUtility == null)
                    {
                        serviceProviderUtility = new ServiceProviderUtility(Context);
                        Cache["spu"] = serviceProviderUtility;
                    }

                    authnResponse = serviceProviderUtility.GetAuthnResponse(Context);
                }
                catch (Saml2Exception se)
                {
                    errorMessage = se.Message;
                    errorTrace = se.StackTrace;
                    if (se.InnerException != null)
                        errorTrace += "<br/>" + se.InnerException.StackTrace;
                }
                catch (ServiceProviderUtilityException spue)
                {
                    errorMessage = spue.Message;
                    errorTrace = spue.StackTrace;
                    if (spue.InnerException != null)
                        errorTrace += "<br/>" + spue.InnerException.StackTrace;
                }


                String userName = null;
                if (authnResponse != null)
                {
                    FedletUser User = new FedletUser();
                    User.UserName = authnResponse.SubjectNameId;

                    userName = authnResponse.SubjectNameId;
                    foreach (string AttributeName in authnResponse.Attributes.Keys)
                    {
                        ArrayList AttributeValues = authnResponse.Attributes[AttributeName] as ArrayList;
                        string AttributeValue = "";
                        if (AttributeValues.Count > 0)
                        {
                            AttributeValue = AttributeValues[0] as String;
                        }

                        User.Attributes[AttributeName] = AttributeValue;
                        
                    }

                    Session["FedletUser"] = User;

                    if (Request["RelayState"] != null)
                    {
                        Response.Redirect(Request["RelayState"]);
                    }
                    else
                    {
                        Response.Redirect(WebConfigurationManager.AppSettings["fedletController.defaultRelayState"]);
                    }
                }
                else
                {
                    userName = errorMessage;
                }

                

                

            }
            else
            {
                Response.StatusCode = 500;
                Response.StatusDescription = "Not a valid saml2 action";
            }

            
        }
        public bool IsReusable
        {
            // To enable pooling, return true here.
            // This keeps the handler in memory.
            get { return false; }
        }
    }
}
