using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Andy.Auth.Revocation;

public sealed class RevocationReceiverKeys(IOptions<RevocationReceiverOptions> options, IHttpClientFactory clients)
{
    public IConfigurationManager<OpenIdConnectConfiguration> Manager { get; set; } =
        new ConfigurationManager<OpenIdConnectConfiguration>(
            options.Value.Authority.TrimEnd('/') + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(clients.CreateClient("Andy.Auth.RevocationMetadata")) { RequireHttps = true });
}

public sealed class RevocationReceiver(IOptions<RevocationReceiverOptions> options, RevocationReceiverKeys keys,
    IRevokedSessionStore store, TimeProvider clock)
{
    public const string EventType = "urn:rivoli:params:secevent:session-revoked";

    public async Task<IResult> ReceiveAsync(HttpContext context)
    {
        if (!context.Request.IsHttps) return Results.StatusCode(400);
        if (!Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(context.Request.ContentType, out var contentType) ||
            !string.Equals(contentType.MediaType.Value, "application/secevent+jwt", StringComparison.OrdinalIgnoreCase))
            return Results.StatusCode(415);
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            var tokenText = new StringBuilder();
            using var reader = new StreamReader(context.Request.Body, Encoding.ASCII, false, 2048, leaveOpen: true);
            var buffer = new char[2048];
            int count;
            while ((count = await reader.ReadAsync(buffer.AsMemory(), context.RequestAborted)) > 0)
            {
                tokenText.Append(buffer, 0, count);
                if (tokenText.Length > 32768) return Results.StatusCode(413);
            }
            var untrusted = new JsonWebToken(tokenText.ToString());
            if (untrusted.Alg != SecurityAlgorithms.RsaSha256 || untrusted.Typ != "secevent+jwt" ||
                string.IsNullOrWhiteSpace(untrusted.Kid) || untrusted.Kid.Length > 256)
                return Invalid(context);
            var metadata = await keys.Manager.GetConfigurationAsync(context.RequestAborted);
            if (!metadata.SigningKeys.Any(key => key.KeyId == untrusted.Kid))
            {
                keys.Manager.RequestRefresh();
                context.Response.Headers.RetryAfter = "5";
                return Results.StatusCode(503);
            }
            var validated = await new JsonWebTokenHandler().ValidateTokenAsync(tokenText.ToString(), new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = options.Value.Authority,
                ValidateAudience = true, ValidAudience = options.Value.Audience,
                ValidateIssuerSigningKey = true, IssuerSigningKeys = metadata.SigningKeys,
                ValidTypes = new[] { "secevent+jwt" }, ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
                RequireSignedTokens = true, RequireExpirationTime = false, ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            });
            if (!validated.IsValid) return Invalid(context);
            var token = (JsonWebToken)validated.SecurityToken;
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (!token.TryGetPayloadValue<long>("iat", out var issued) || issued < now - 300 || issued > now + 60 ||
                !Guid.TryParseExact(token.Id, "N", out _) ||
                !token.TryGetPayloadValue<JsonElement>("events", out var events) ||
                events.ValueKind != JsonValueKind.Object || events.EnumerateObject().Count() != 1 ||
                !events.TryGetProperty(EventType, out var payload) || payload.ValueKind != JsonValueKind.Object ||
                !payload.TryGetProperty("sid", out var sid) || sid.ValueKind != JsonValueKind.String ||
                !payload.TryGetProperty("occurred_at", out var occurred) || !occurred.TryGetInt64(out var occurredAt) ||
                occurredAt < 0 || occurredAt > issued + 60)
                return Invalid(context);
            var session = sid.GetString();
            if (string.IsNullOrWhiteSpace(session) || session.Length > 256 || session.Any(char.IsControl))
                return Invalid(context);
            // Receipt only denies this session. Replaying the same SET cannot
            // restore authority or repeat an external side effect. It extends
            // the same durable denial, and receives the same 202 acknowledgment.
            await store.RevokeAsync(options.Value.Authority, session, context.RequestAborted);
            return Results.StatusCode(202);
        }
        catch (Exception error) when (error is JsonException or ArgumentException or SecurityTokenException)
        {
            return Invalid(context);
        }
        catch (Exception)
        {
            context.Response.Headers.RetryAfter = "5";
            return Results.StatusCode(503); // never acknowledge before durable receipt
        }
    }

    private static IResult Invalid(HttpContext context)
    {
        context.Response.Headers.ContentLanguage = "en";
        return Results.Json(new { err = "invalid_request", description = "The security event could not be validated." }, statusCode: 400);
    }
}

public static class RevocationReceiverRegistration
{
    public static IServiceCollection AddAndyRevocationReceiver(this IServiceCollection services, Action<RevocationReceiverOptions> configure)
    {
        services.AddOptions<RevocationReceiverOptions>().Configure(configure)
            .Validate(options => options.IsValid(), "Security event receipt requires HTTPS authority, audience, and bounded retention.").ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IRevokedSessionStore, DistributedRevokedSessionStore>();
        services.AddHostedService<RequireRevocationStoreStartup>();
        services.AddSingleton<RevocationReceiverKeys>();
        services.AddScoped<RevocationReceiver>();
        services.AddHttpClient("Andy.Auth.RevocationMetadata", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(5);
            client.MaxResponseContentBufferSize = 256 * 1024;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        return services;
    }

    public static IEndpointConventionBuilder MapAndyRevocationEvents(this IEndpointRouteBuilder endpoints,
        string pattern = "/auth/events") => endpoints.MapPost(pattern,
            (HttpContext context, RevocationReceiver receiver) => receiver.ReceiveAsync(context)).AllowAnonymous();
}
