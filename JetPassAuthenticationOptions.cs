using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// Configuration options for <see cref="JetPassAuthenticationMiddleware"/>
  /// </summary>
  public class JetPassAuthenticationOptions : AuthenticationOptions
  {
    public class JetPassAuthenticationEndpoints
    {
      public JetPassAuthenticationEndpoints() : this(new Uri("https://hub.jetbrains.com")) { }
      public JetPassAuthenticationEndpoints(Uri rootUri)
      {
        AuthorizationEndpoint = new Uri(rootUri, "/rest/oauth2/auth").AbsoluteUri;
        TokenEndpoint = new Uri(rootUri, "/rest/oauth2/token").AbsoluteUri;
        UserInfoEndpoint = new Uri(rootUri, "/rest/users/me").AbsoluteUri;
      }

      /// <summary>
      /// Endpoint which is used to redirect users to request JetPass access
      /// </summary>
      /// <remarks>
      /// Defaults to https://hub.jetbrains.com/rest/oauth2/auth
      /// </remarks>
      public string AuthorizationEndpoint { get; set; }

      /// <summary>
      /// Endpoint which is used to exchange code for access token
      /// </summary>
      /// <remarks>
      /// Defaults to https://hub.jetbrains.com/rest/oauth2/token
      /// </remarks>
      public string TokenEndpoint { get; set; }

      /// <summary>
      /// Endpoint which is used to obtain user information after authentication
      /// </summary>
      /// <remarks>
      /// Defaults to https://hub.jetbrains.com/rest/users/me
      /// </remarks>
      public string UserInfoEndpoint { get; set; }
    }

    /// <summary>
    /// Initializes a new <see cref="JetPassAuthenticationOptions"/>
    /// </summary>
    public JetPassAuthenticationOptions()
      : base(Constants.DefaultAuthenticationType)
    {
      Caption = Constants.DefaultAuthenticationType;
      CallbackPath = new PathString("/JetPass");
      AuthenticationMode = AuthenticationMode.Passive;
      Scope = new List<string>();
      BackchannelTimeout = TimeSpan.FromSeconds(60);
      Endpoints = new JetPassAuthenticationEndpoints();
    }

    /// <summary>
    /// Gets or sets the JetPass-assigned client id
    /// </summary>
    public string ClientId { get; set; }

    /// <summary>
    /// Gets or sets the JetPass-assigned client secret
    /// </summary>
    public string ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets OAuth endpoints root used to authenticate against JetPass.
    /// </summary>
    public JetPassAuthenticationEndpoints Endpoints { get; set; }

    /// <summary>
    /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
    /// in back channel communications belong to JetPass.
    /// </summary>
    /// <value>
    /// The pinned certificate validator.
    /// </value>
    /// <remarks>If this property is null then the default certificate checks are performed,
    /// validating the subject name and if the signing chain is a trusted party.</remarks>
    public ICertificateValidator BackchannelCertificateValidator { get; set; }

    /// <summary>
    /// Gets or sets timeout value in milliseconds for back channel communications with JetPass.
    /// </summary>
    /// <value>
    /// The back channel timeout in milliseconds.
    /// </value>
    public TimeSpan BackchannelTimeout { get; set; }

    /// <summary>
    /// The HttpMessageHandler used to communicate with JetPass.
    /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
    /// can be downcast to a WebRequestHandler.
    /// </summary>
    public HttpMessageHandler BackchannelHttpHandler { get; set; }

    /// <summary>
    /// Get or sets the text that the user can display on a sign in user interface.
    /// </summary>
    public string Caption { get { return Description.Caption; } set { Description.Caption = value; } }

    /// <summary>
    /// The request path within the application's base path where the user-agent will be returned.
    /// The middleware will process this request when it arrives.
    /// Default value is "/JetPass".
    /// </summary>
    public PathString CallbackPath { get; set; }

    /// <summary>
    /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public string SignInAsAuthenticationType { get; set; }

    /// <summary>
    /// Gets or sets the <see cref="IJetPassAuthenticationProvider"/> used to handle authentication events.
    /// </summary>
    public IJetPassAuthenticationProvider Provider { get; set; }

    /// <summary>
    /// Gets or sets the type used to secure data handled by the middleware.
    /// </summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

    /// <summary>
    /// A list of permissions to request.
    /// </summary>
    public IReadOnlyList<string> Scope { get; set; }
  }
}