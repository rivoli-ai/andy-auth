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

    private static string MintToken(SigningCredentials creds, string issuer, string sub)
    {
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Subject = new ClaimsIdentity(new[] { new Claim("sub", sub) }),
            Expires = DateTime.UtcNow.AddMinutes(5),
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

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
