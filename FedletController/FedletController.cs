using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Routing;
using Sun.Identity.Saml2;
using Sun.Identity.Saml2.Exceptions;
using System.Xml;
using System.Configuration;
using System.Reflection;
using System.Web.SessionState;
using System.Diagnostics;
using System.Web.Configuration;

namespace gov.dhs.uscis.icam.fedlet
{
    class FedletController : IHttpModule
    {
        private HttpApplication application;

        private Dictionary<string, string> attr2header;
        private LinkedList<string> ignoreURIs;
        private bool inversIgnoreList;

        public void Init(HttpApplication context)
        {
            


            application = context;
            application.BeginRequest += new EventHandler(ApplicationHTTP_BeginRequest);
            application.EndRequest += new EventHandler(ApplicationHTTP_EndRequest);

            application.PostAcquireRequestState += new EventHandler(Application_PostAcquireRequestState);
            application.PostMapRequestHandler += new EventHandler(Application_PostMapRequestHandler);

            this.attr2header = new Dictionary<string, string>();

            int numAttrs = int.Parse(WebConfigurationManager.AppSettings["fedletController.numAttrs"]);
            for (int i = 0; i < numAttrs; i++)
            {
                string Attr = WebConfigurationManager.AppSettings["fedletController.attribute." + i];
                string HeaderName = Attr.Substring(0, Attr.IndexOf("="));
                string AttributeName = Attr.Substring(Attr.IndexOf("=") + 1);
                attr2header[AttributeName] = HeaderName;
            }

            this.ignoreURIs = new LinkedList<string>();
            int numIgnoreURIs = int.Parse(WebConfigurationManager.AppSettings["fedletController.numIgnoreURIs"]);
            for (int i = 0; i < numIgnoreURIs; i++)
            {
                ignoreURIs.AddLast(WebConfigurationManager.AppSettings["fedletController.ignoreURI." + i]);
            }

            this.inversIgnoreList = bool.Parse(WebConfigurationManager.AppSettings["fedletController.inverseIgnoreList"]);
        }



        void ApplicationHTTP_BeginRequest(object sender, EventArgs e)
        {
            
            

        }
        void ApplicationHTTP_EndRequest(object sender, EventArgs e)
        {

        }

        

        public void Dispose()
        {

        }

        void Application_PostMapRequestHandler(object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;

            if (app.Context.Handler is IReadOnlySessionState || app.Context.Handler is IRequiresSessionState)
            {
                // no need to replace the current handler
                return;
            }

            // swap the current handler
            app.Context.Handler = new MyHttpHandler(app.Context.Handler);
        }

        void Application_PostAcquireRequestState(object source, EventArgs e)
        {
            HttpApplication app = (HttpApplication)source;

            MyHttpHandler resourceHttpHandler = HttpContext.Current.Handler as MyHttpHandler;

            if (resourceHttpHandler != null)
            {
                // set the original handler back
                HttpContext.Current.Handler = resourceHttpHandler.OriginalHandler;
            }

            // -> at this point session state should be available
            Debug.Assert(app.Session != null, "Session not available");


            HttpApplication Application = (HttpApplication)source;
            if (!Application.Request.Url.AbsoluteUri.EndsWith(".saml2"))
            {
                if (Application.Session["FedletUser"] != null)
                {
                    //The user is already logged in
                    FedletUser User = Application.Session["FedletUser"] as FedletUser;
                    String UserNameHeaderName = WebConfigurationManager.AppSettings["fedletController.userNameHeader"];
                    app.Request.Headers.Remove(UserNameHeaderName);
                    app.Request.Headers.Add(UserNameHeaderName, User.UserName);

                    foreach (string AttributeName in User.Attributes.Keys)
                    {
                        string HeaderName = AttributeName;
                        if (this.attr2header.ContainsKey(AttributeName)) 
                        { 
                            HeaderName = this.attr2header[AttributeName];
                        }


                  

                        app.Request.Headers.Remove(HeaderName);
                        app.Request.Headers.Add(HeaderName, User.Attributes[AttributeName]);
                        
                    }

                }
                else
                {
                    //The user is NOT logged in
                    bool matchesIgnoreList = false;

                    foreach (string URI in this.ignoreURIs) 
                    {
                        //throw new Exception("URI : '" + URI + "' / '" + app.Request.Url.AbsolutePath + "'");
                        
                        if (URI.StartsWith("/"))
                        {
                            if (app.Request.Url.AbsolutePath.StartsWith(URI))
                            {
                                matchesIgnoreList = true;
                                break;
                            }
                        }
                        else
                        {
                            if (app.Request.Url.Equals(URI))
                            {
                                matchesIgnoreList = true;
                                break;
                            }
                        }
                        
                    }

                    if (matchesIgnoreList)
                    {
                        if (this.inversIgnoreList)
                        {
                            AuthenticateUser(app);
                        }
                    }
                    else
                    {
                        if (!this.inversIgnoreList)
                        {
                            AuthenticateUser(app);
                        }
                    }

                    
                }

                
                
            }
        }

        private static void AuthenticateUser(HttpApplication app)
        {
            app.Response.Redirect(WebConfigurationManager.AppSettings["fedletController.loginURL"] + "&RelayState=" + app.Request.Url);
        }

        // a temp handler used to force the SessionStateModule to load session state
        public class MyHttpHandler : IHttpHandler, IRequiresSessionState
        {
            internal readonly IHttpHandler OriginalHandler;

            public MyHttpHandler(IHttpHandler originalHandler)
            {
                OriginalHandler = originalHandler;
            }

            public void ProcessRequest(HttpContext context)
            {
                // do not worry, ProcessRequest() will not be called, but let's be safe
                throw new InvalidOperationException("MyHttpHandler cannot process requests.");
            }

            public bool IsReusable
            {
                // IsReusable must be set to false since class has a member!
                get { return false; }
            }
        }
    }
}
