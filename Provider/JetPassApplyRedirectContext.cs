using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// Context passed when a Challenge causes a redirect to authorize endpoint in the JetPass OAuth 2.0 middleware
  /// </summary>
  public class JetPassApplyRedirectContext : BaseContext<JetPassAuthenticationOptions>
  {
    /// <summary>
    /// Creates a new context object.
    /// </summary>
    /// <param name="context">The OWIN request context</param>
    /// <param name="options">The JetPass OAuth 2.0 middleware options</param>
    /// <param name="properties">The authentication properties of the challenge</param>
    /// <param name="redirectUri">The initial redirect URI</param>
    public JetPassApplyRedirectContext(IOwinContext context, JetPassAuthenticationOptions options, AuthenticationProperties properties, string redirectUri)
      : base(context, options)
    {
      RedirectUri = redirectUri;
      Properties = properties;
    }

    /// <summary>
    /// Gets the URI used for the redirect operation.
    /// </summary>
    public string RedirectUri { get; private set; }

    /// <summary>
    /// Gets the authentication properties of the challenge
    /// </summary>
    public AuthenticationProperties Properties { get; private set; }
  }
}