using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Andy.Auth.Services;

/// <summary>Request-time session authority for user-bound high-risk resources.</summary>
public static class LiveSessionValidation
{
    public const string HttpClientName = "Andy.Auth.SessionTruth";
    private static readonly object Unavailable = new();

    public static JwtBearerEvents Create(JwtBearerEvents original, Uri endpoint)
    {
        var events = new JwtBearerEvents
        {
            OnMessageReceived = original.MessageReceived,
            OnAuthenticationFailed = original.AuthenticationFailed,
            OnForbidden = original.Forbidden
        };
        var validated = original.TokenValidated;
        var challenged = original.Challenge;
        events.OnTokenValidated = async context =>
        {
            await validated(context);
            if (context.Result?.Failure != null) return;
            var subject = context.Principal?.FindFirst("sub")?.Value
                ?? context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var session = context.Principal?.FindFirst("session_id")?.Value;
            if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(session))
            {
                context.Fail("A user-bound session is required by this resource.");
                return;
            }
            // Use the signed token that the bearer handler actually validated;
            // custom token retrieval must not cause a different header to be sent.
            var token = context.SecurityToken switch
            {
                Microsoft.IdentityModel.JsonWebTokens.JsonWebToken jwt => jwt.EncodedToken,
                System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwt => jwt.RawData,
                _ => null
            };
            if (string.IsNullOrEmpty(token))
            {
                context.Fail("The validated access token is unavailable.");
                return;
            }
            try
            {
                var client = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>()
                    .CreateClient(HttpClientName);
                using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
                using var response = await client.SendAsync(request, context.HttpContext.RequestAborted);
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Gone or HttpStatusCode.Forbidden)
                {
                    context.Fail("The session is no longer authorized.");
                    return;
                }
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new HttpRequestException("Session authority is unavailable.");
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted));
                var truth = body.RootElement;
                if (!truth.GetProperty("authenticated").GetBoolean() || truth.GetProperty("revoked").GetBoolean() ||
                    truth.GetProperty("subject").GetString() != subject || truth.GetProperty("sessionId").GetString() != session)
                    context.Fail("The session authority did not confirm this exact subject and session.");
                var claimedRoles = context.Principal!.Claims
                    .Where(claim => claim.Type is ClaimTypes.Role or "role" or "roles").Select(claim => claim.Value).ToArray();
                if (context.Result?.Failure == null && claimedRoles.Length > 0)
                {
                    var roles = truth.GetProperty("roles").EnumerateArray().Select(role => role.GetString()).ToHashSet(StringComparer.Ordinal);
                    if (claimedRoles.Any(role => !roles.Contains(role)))
                        context.Fail("The account no longer holds all roles carried by this token.");
                }
            }
            catch (Exception error) when (error is HttpRequestException or OperationCanceledException or JsonException or
                KeyNotFoundException or InvalidOperationException)
            {
                context.HttpContext.Items[Unavailable] = true;
                context.Fail("Session authority is temporarily unavailable.");
            }
        };
        events.OnChallenge = async context =>
        {
            if (context.HttpContext.Items.ContainsKey(Unavailable))
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers.RetryAfter = "5";
                return;
            }
            await challenged(context);
        };
        return events;
    }
}
