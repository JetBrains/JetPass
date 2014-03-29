using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace JetBrains.Owin.Security.JetPass
{
  internal class JetPassAuthenticationHandler : AuthenticationHandler<JetPassAuthenticationOptions>
  {
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    
    public JetPassAuthenticationHandler(HttpClient httpClient, ILogger logger)
    {
      _httpClient = httpClient;
      _logger = logger;
    }

    protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
    {
      AuthenticationProperties properties = null;
      try
      {
        string code = null;
        string state = null;
        var query = Request.Query;
        var values = query.GetValues("code");
        if (values != null && values.Count == 1)
        {
          code = values[0];
        }
        values = query.GetValues("state");
        if (values != null && values.Count == 1)
        {
          state = values[0];
        }
        properties = Options.StateDataFormat.Unprotect(state);
        if (properties == null)
        {
          return null;
        }

        // OAuth2 10.12 CSRF
        if (!ValidateCorrelationId(properties, _logger))
        {
          return new AuthenticationTicket(null, properties);
        }
        string requestPrefix = Request.Scheme + "://" + Request.Host;
        string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

        // Build up the body for the token request
        var body = new Dictionary<string, string>
        {
          { "grant_type", "authorization_code" },
          { "code", code },
          { "redirect_uri", redirectUri }
        };
        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint)
        {
          Content = new FormUrlEncodedContent(body),
        };
        tokenRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic",
          Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", Options.ClientId, Options.ClientSecret))));
        // Request the token
        var tokenResponse = await _httpClient.SendAsync(tokenRequest);
        tokenResponse.EnsureSuccessStatusCode();
        var text = await tokenResponse.Content.ReadAsStringAsync();

        // Deserializes the token response
        JObject response = JObject.Parse(text);
        var accessToken = response.Value<string>("access_token");
        var expires = response.Value<string>("expires_in");
        var refreshToken = response.Value<string>("refresh_token");
        if (string.IsNullOrWhiteSpace(accessToken))
        {
          _logger.WriteWarning("Access token was not found");
          return new AuthenticationTicket(null, properties);
        }

        // Get the JetPass user
        var userRequest = new HttpRequestMessage(HttpMethod.Get, Options.Endpoints.UserInfoEndpoint);
        userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var graphResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);
        graphResponse.EnsureSuccessStatusCode();
        text = await graphResponse.Content.ReadAsStringAsync();
        var user = JObject.Parse(text);
        var context = new JetPassAuthenticatedContext(Context, user, accessToken, refreshToken, expires);
        context.Identity = new ClaimsIdentity(
          Options.AuthenticationType,
          ClaimsIdentity.DefaultNameClaimType,
          ClaimsIdentity.DefaultRoleClaimType);
        if (!string.IsNullOrEmpty(context.Id))
        {
          context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id,
            ClaimValueTypes.String, Options.AuthenticationType));
        }
        if (!string.IsNullOrEmpty(context.Name))
        {
          context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.Name, ClaimValueTypes.String,
            Options.AuthenticationType));
        }
        foreach (var email in context.Emails)
        {
          context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String,
            Options.AuthenticationType));
        }
        context.Properties = properties;
        await Options.Provider.Authenticated(context);
        return new AuthenticationTicket(context.Identity, context.Properties);
      }
      catch (Exception ex)
      {
        _logger.WriteError("Authentication failed", ex);
        return new AuthenticationTicket(null, properties);
      }
    }

    protected override Task ApplyResponseChallengeAsync()
    {
      if (Response.StatusCode != 401)
      {
        return Task.FromResult<object>(null);
      }
      var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
      if (challenge != null)
      {
        string baseUri =
          Request.Scheme +
          Uri.SchemeDelimiter +
          Request.Host +
          Request.PathBase;
        string currentUri =
          baseUri +
          Request.Path +
          Request.QueryString;
        string redirectUri =
          baseUri +
          Options.CallbackPath;
        var properties = challenge.Properties;
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
          properties.RedirectUri = currentUri;
        }

        // OAuth2 10.12 CSRF
        GenerateCorrelationId(properties);
        var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
          { "response_type", "code" },
          { "client_id", Options.ClientId },
          { "redirect_uri", redirectUri }
        };

        // space separated scopes
        // always retrieve 0-0-0-0-0 scope, for user info retrieving
        var scope = string.Join(" ", Options.Scope.Concat(new[] { "0-0-0-0-0" }));
        AddQueryString(queryStrings, properties, "scope", scope);
        AddQueryString(queryStrings, properties, "access_type");
        AddQueryString(queryStrings, properties, "approval_prompt");
        AddQueryString(queryStrings, properties, "login_hint");
        string state = Options.StateDataFormat.Protect(properties);
        queryStrings.Add("state", state);
        string authorizationEndpoint = WebUtilities.AddQueryString(Options.Endpoints.AuthorizationEndpoint, queryStrings);
        var redirectContext = new JetPassApplyRedirectContext(
          Context, Options,
          properties, authorizationEndpoint);
        Options.Provider.ApplyRedirect(redirectContext);
      }
      return Task.FromResult<object>(null);
    }

    public override async Task<bool> InvokeAsync() { return await InvokeReplyPathAsync(); }

    private async Task<bool> InvokeReplyPathAsync()
    {
      if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
      {
        // TODO: error responses
        var ticket = await AuthenticateAsync();
        if (ticket == null)
        {
          _logger.WriteWarning("Invalid return state, unable to redirect.");
          Response.StatusCode = 500;
          return true;
        }
        
        var context = new JetPassReturnEndpointContext(Context, ticket)
        {
          SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
          RedirectUri = ticket.Properties.RedirectUri
        };
        await Options.Provider.ReturnEndpoint(context);
        
        if (context.SignInAsAuthenticationType != null && context.Identity != null)
        {
          var grantIdentity = context.Identity;
          if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
          {
            grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
          }
          Context.Authentication.SignIn(context.Properties, grantIdentity);
        }

        if (!context.IsRequestCompleted && context.RedirectUri != null)
        {
          string redirectUri = context.RedirectUri;
          if (context.Identity == null)
          {
            // add a redirect hint that sign-in failed in some way
            redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
          }
          Response.Redirect(redirectUri);
          context.RequestCompleted();
        }
        
        return context.IsRequestCompleted;
      }
      return false;
    }

    private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties, string name, string defaultValue = null)
    {
      string value;
      if (!properties.Dictionary.TryGetValue(name, out value))
      {
        value = defaultValue;
      }
      else
      {
        // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
        properties.Dictionary.Remove(name);
      }
      if (value == null)
      {
        return;
      }
      queryStrings[name] = value;
    }
  }
}