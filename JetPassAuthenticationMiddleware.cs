using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// OWIN middleware for authenticating users using JetPass OAuth 2.0
  /// </summary>
  public class JetPassAuthenticationMiddleware : AuthenticationMiddleware<JetPassAuthenticationOptions>
  {
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Initializes a <see cref="JetPassAuthenticationMiddleware"/>
    /// </summary>
    /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
    /// <param name="app">The OWIN application</param>
    /// <param name="options">Configuration options for the middleware</param>
    public JetPassAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, JetPassAuthenticationOptions options)
      : base(next, options)
    {
      if (string.IsNullOrWhiteSpace(Options.ClientId))
      {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientId"));
      }
      if (string.IsNullOrWhiteSpace(Options.ClientSecret))
      {
        throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ClientSecret"));
      }
      
      _logger = app.CreateLogger<JetPassAuthenticationMiddleware>();
      
      if (Options.Provider == null)
      {
        Options.Provider = new JetPassAuthenticationProvider();
      }

      if (Options.StateDataFormat == null)
      {
        var dataProtecter = app.CreateDataProtector(
          typeof (JetPassAuthenticationMiddleware).FullName,
          Options.AuthenticationType, "v1");
        Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
      }

      if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
      {
        Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
      }

      _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
      {
        Timeout = Options.BackchannelTimeout,
        MaxResponseContentBufferSize = 1024*1024*10 // 10 MB
      };
    }

    /// <summary>
    /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
    /// </summary>
    /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="JetPassAuthenticationOptions"/> supplied to the constructor.</returns>
    protected override AuthenticationHandler<JetPassAuthenticationOptions> CreateHandler() { return new JetPassAuthenticationHandler(_httpClient, _logger); }

    private static HttpMessageHandler ResolveHttpMessageHandler(JetPassAuthenticationOptions options)
    {
      HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

      // If they provided a validator, apply it or fail.
      if (options.BackchannelCertificateValidator != null)
      {
        // Set the cert validate callback
        var webRequestHandler = handler as WebRequestHandler;
        if (webRequestHandler == null)
        {
          throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
        }
        webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
      }

      return handler;
    }
  }
}