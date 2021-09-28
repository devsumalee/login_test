// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using graph_tutorial.Helpers;
using graph_tutorial.TokenStorage;
using System.Security.Claims;

namespace graph_tutorial
{
    public class Startup
    {
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
        string Secret = System.Configuration.ConfigurationManager.AppSettings["Secret"];
        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
        string graphScopes = System.Configuration.ConfigurationManager.AppSettings["AppScopes"];
        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        static string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];

    // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
    string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"], tenant);

  public void Configuration(IAppBuilder app)
    {
        app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

        app.UseCookieAuthentication(new CookieAuthenticationOptions());
        app.UseOpenIdConnectAuthentication(
        new OpenIdConnectAuthenticationOptions
        {
           
                ClientId = clientId,
            Authority = authority,
            RedirectUri = redirectUri,
                PostLogoutRedirectUri = redirectUri,
            //Scope = OpenIdConnectScope.OpenIdProfile,
           Scope = $"openid profile offline_access {graphScopes}",
            ResponseType = OpenIdConnectResponseType.CodeIdToken,
            TokenValidationParameters = new TokenValidationParameters
            {
                //    // For demo purposes only, see below
                ValidateIssuer = false
            },
            Notifications = new OpenIdConnectAuthenticationNotifications
            {
                AuthenticationFailed = OnAuthenticationFailed,

                AuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
            }
        }
    );
    }

    /// <summary>
    /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
    {
            if (context.Exception.Message.Contains("IDX21323"))
            {
                context.HandleResponse();
                context.OwinContext.Authentication.Challenge();
         
            //context.HandleResponse();
        context.Response.Redirect("/?errormessage1=" + context.Exception.Message);   
            }
        return Task.FromResult(0);
    }
        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            notification.HandleCodeRedemption();


            //IConfidentialClientApplication clientApp = MsalAppBuilder.BuildConfidentialClientApplication();
            //AuthenticationResult result = await clientApp.AcquireTokenByAuthorizationCode(new[] { "Mail.Read" }, notification.Code).ExecuteAsync();



            IConfidentialClientApplication idClient = ConfidentialClientApplicationBuilder.Create(clientId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(Secret)
                .WithAuthority(new Uri(authority))
                 .Build();

            ////var signedInUser = new ClaimsPrincipal(notification.AuthenticationTicket.Identity);
            ////var tokenStore = new SessionTokenStore(idClient.UserTokenCache, HttpContext.Current, signedInUser);

            try
            {
                string[] scopes = graphScopes.Split(' ');

                var result = await idClient.AcquireTokenByAuthorizationCode(
                    scopes, notification.Code).ExecuteAsync();
                notification.Response.Redirect($"/Home/Error?errormessage1={result}&debug={1}");

            }
            catch (MsalException ex)
            {
                string message = "AcquireTokenByAuthorizationCodeAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?errormessage1={message}&debug={ex.Message}");
            }

        }
    }
}
