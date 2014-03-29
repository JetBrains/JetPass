using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// Provides context information to middleware providers.
  /// </summary>
  public class JetPassReturnEndpointContext : ReturnEndpointContext
  {
    /// <summary>
    /// Initialize a <see cref="JetPassReturnEndpointContext"/>
    /// </summary>
    /// <param name="context">OWIN environment</param>
    /// <param name="ticket">The authentication ticket</param>
    public JetPassReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
      : base(context, ticket) { }
  }
}