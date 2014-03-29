using System.Threading.Tasks;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// Specifies callback methods which the <see cref="JetPassAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
  /// </summary>
  public interface IJetPassAuthenticationProvider
  {
    /// <summary>
    /// Invoked whenever Google successfully authenticates a user
    /// </summary>
    /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    Task Authenticated(JetPassAuthenticatedContext context);

    /// <summary>
    /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
    /// </summary>
    /// <param name="context">Contains context information and authentication ticket of the return endpoint.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    Task ReturnEndpoint(JetPassReturnEndpointContext context);

    /// <summary>
    /// Called when a Challenge causes a redirect to authorize endpoint in the JetPass OAuth 2.0 middleware
    /// </summary>
    /// <param name="context">Contains redirect URI and <see cref="Microsoft.Owin.Security.AuthenticationProperties"/> of the challenge </param>
    void ApplyRedirect(JetPassApplyRedirectContext context);
  }
}