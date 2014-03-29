using System;
using JetBrains.Owin.Security.JetPass;

namespace Owin
{
  /// <summary>
  /// Extension methods for using <see cref="JetPassAuthenticationMiddleware"/>
  /// </summary>
  public static class JetPassAuthenticationExtensions
  {
    /// <summary>
    /// Authenticate users using JetPass OAuth 2.0
    /// </summary>
    /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
    /// <param name="options">Middleware configuration options</param>
    /// <returns>The updated <see cref="IAppBuilder"/></returns>
    public static IAppBuilder UseJetPassAuthentication(this IAppBuilder app, JetPassAuthenticationOptions options)
    {
      if (app == null)
      {
        throw new ArgumentNullException("app");
      }
      if (options == null)
      {
        throw new ArgumentNullException("options");
      }
      app.Use(typeof (JetPassAuthenticationMiddleware), app, options);
      return app;
    }

    /// <summary>
    /// Authenticate users using JetPass OAuth 2.0
    /// </summary>
    /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
    /// <param name="clientId">The JetPass assigned client id</param>
    /// <param name="clientSecret">The JetPass assigned client secret</param>
    /// <returns>The updated <see cref="IAppBuilder"/></returns>
    public static IAppBuilder UseJetPassAuthentication(this IAppBuilder app, string clientId, string clientSecret)
    {
      return UseJetPassAuthentication(app,
        new JetPassAuthenticationOptions
        {
          ClientId = clientId,
          ClientSecret = clientSecret
        });
    }
  }
}