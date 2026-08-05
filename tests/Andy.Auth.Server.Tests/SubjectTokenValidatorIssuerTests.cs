using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Andy.Auth.Server.Services;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Xunit;

namespace Andy.Auth.Server.Tests;

/// <summary>
/// Regression guard for rivoli-ai/conductor#1973: the RFC 8693 subject-token
/// validator must accept the `iss` claim whether or not it carries a trailing
/// slash. OpenIddict emits `iss` verbatim from the configured issuer URI
/// (which has a trailing slash, e.g. "https://auth.example/"); a single
/// trimmed ValidIssuer was an exact-match miss, rejecting every OBO exchange
/// with invalid_grant.
/// </summary>
public class SubjectTokenValidatorIssuerTests
{
    private const string IssuerWithSlash = "https://auth.example/";

    private static (InProcessSubjectTokenValidator validator, SigningCredentials creds) BuildValidator()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('k', 64)));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var options = new OpenIddictServerOptions { Issuer = new Uri(IssuerWithSlash) };
        options.SigningCredentials.Add(creds);

        var monitor = new StaticOptionsMonitor<OpenIddictServerOptions>(options);
        return (new InProcessSubjectTokenValidator(monitor, NullLogger<InProcessSubjectTokenValidator>.Instance), creds);
    }

    private static string MintToken(
        SigningCredentials creds,
        string issuer,
        string sub,
        string tokenType = "at+jwt",
        string? audience = null,
        DateTime? expires = null,
        IEnumerable<Claim>? additionalClaims = null)
    {
        var handler = new JsonWebTokenHandler();
        var claims = new List<Claim> { new("sub", sub) };
        if (additionalClaims is not null)
        {
            claims.AddRange(additionalClaims);
        }

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            TokenType = tokenType,
            Subject = new ClaimsIdentity(claims),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = creds,
        });
    }

    [Theory]
    [InlineData("https://auth.example/")]  // verbatim — how OpenIddict actually emits iss
    [InlineData("https://auth.example")]   // trimmed — must also be accepted
    public async Task ValidateAsync_AcceptsIssuer_WithOrWithoutTrailingSlash(string tokenIssuer)
    {
        var (validator, creds) = BuildValidator();
        var token = MintToken(creds, tokenIssuer, "user-123");

        var result = await validator.ValidateAsync(token);

        result.IsValid.Should().BeTrue("the validator must accept both issuer forms");
        result.Subject.Should().Be("user-123");
    }

    [Fact]
    public async Task ValidateAsync_RejectsToken_FromADifferentIssuer()
    {
        var (validator, creds) = BuildValidator();
        var token = MintToken(creds, "https://evil.example/", "user-123");

        var result = await validator.ValidateAsync(token);

        result.IsValid.Should().BeFalse("a token from an unrelated issuer must still be rejected");
    }

    [Theory]
    [InlineData("JWT")]
    [InlineData("id+jwt")]
    public async Task ValidateAsync_RejectsLocallySignedNonAccessToken(string tokenType)
    {
        var (validator, creds) = BuildValidator();
        var token = MintToken(
            creds, IssuerWithSlash, "user-123", tokenType: tokenType);

        var result = await validator.ValidateAsync(token);

        result.IsValid.Should().BeFalse(
            "a valid signature must not turn an ID or generic JWT into an access token");
    }

    [Fact]
    public async Task ValidateAsync_ReturnsVerifiedAudienceExpiryScopesAndSession()
    {
        var (validator, creds) = BuildValidator();
        var expiry = DateTime.UtcNow.AddMinutes(3);
        var token = MintToken(
            creds,
            IssuerWithSlash,
            "user-123",
            audience: "urn:trusted-source-api",
            expires: expiry,
            additionalClaims: new[]
            {
                new Claim("scope", "read write"),
                new Claim(AndyAuthSignInManager.SessionIdClaimType, "session-123")
            });

        var result = await validator.ValidateAsync(token);

        result.IsValid.Should().BeTrue();
        result.Audiences.Should().ContainSingle("urn:trusted-source-api");
        result.Scopes.Should().BeEquivalentTo("read", "write");
        result.SessionId.Should().Be("session-123");
        result.ExpiresAt.Should().BeCloseTo(
            new DateTimeOffset(expiry, TimeSpan.Zero), TimeSpan.FromSeconds(1));
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
