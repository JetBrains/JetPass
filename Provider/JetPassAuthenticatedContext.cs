using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace JetBrains.Owin.Security.JetPass
{
  /// <summary>
  /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
  /// </summary>
  public class JetPassAuthenticatedContext : BaseContext
  {
    /// <summary>
    /// Initializes a <see cref="JetPassAuthenticatedContext"/>
    /// </summary>
    /// <param name="context">The OWIN environment</param>
    /// <param name="user">The JSON-serialized JetPass user info</param>
    /// <param name="accessToken">JetPass OAuth 2.0 access token</param>
    /// <param name="refreshToken">JetPass OAuth 2.0 refresh token</param>
    /// <param name="expires">Seconds until expiration</param>
    public JetPassAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expires)
      : base(context)
    {
      User = user;
      AccessToken = accessToken;
      RefreshToken = refreshToken;
      int expiresValue;
      if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
      {
        ExpiresIn = TimeSpan.FromSeconds(expiresValue);
      }
      Id = TryGetValue(user, "id");
      Name = TryGetValue(user, "name");
      JToken contacts;
      var emails = new List<string>();
      if (user.TryGetValue("contacts", out contacts))
      {
        foreach (var contact in contacts.Values<JObject>())
        {
          if (!contact.Value<bool>("verified")) continue;
          JToken email;
          if (contact.TryGetValue("email", out email))
          {
            emails.Add(email.ToString());
          }
        }
      }
      Emails = emails;
    }

    /// <summary>
    /// Gets the JSON-serialized user
    /// </summary>
    /// <remarks>
    /// Contains the JetPass user obtained from the endpoint https://hub.jetbrains.com/rest/users/me
    /// </remarks>
    public JObject User { get; private set; }

    /// <summary>
    /// Gets the JetPass access token
    /// </summary>
    public string AccessToken { get; private set; }

    /// <summary>
    /// Gets the JetPass refresh token
    /// </summary>
    /// <remarks>
    /// This value is not null only when access_type authorize parameter is offline.
    /// </remarks>
    public string RefreshToken { get; private set; }

    /// <summary>
    /// Gets the JetPass access token expiration time
    /// </summary>
    public TimeSpan? ExpiresIn { get; set; }

    /// <summary>
    /// Gets the JetPass user ID
    /// </summary>
    public string Id { get; private set; }

    /// <summary>
    /// Gets the user's name
    /// </summary>
    public string Name { get; private set; }

    /// <summary>
    /// Gets the user's emails
    /// </summary>
    public IReadOnlyCollection<string> Emails { get; private set; }

    /// <summary>
    /// Gets the <see cref="ClaimsIdentity"/> representing the user
    /// </summary>
    public ClaimsIdentity Identity { get; set; }

    /// <summary>
    /// Gets or sets a property bag for common authentication properties
    /// </summary>
    public AuthenticationProperties Properties { get; set; }

    private static string TryGetValue(JObject user, string propertyName)
    {
      JToken value;
      return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
    }
  }
}