using Andy.Auth.Server.Mcp;
using FluentAssertions;
using Xunit;

namespace Andy.Auth.Server.Tests.Mcp;

/// <summary>
/// andy-auth#155. Found by running the server, not by the unit tests: the first
/// version of this logic only wrote the header when none was present, and
/// OpenIddict's validation handler always writes a bare `Bearer` first — so the
/// RFC 9728 discovery pointer was never actually emitted.
/// </summary>
public class ProtectedResourceChallengeTests
{
    private const string Url = "https://auth.example.com/.well-known/oauth-protected-resource";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NoExistingChallenge_WritesAFullBearerChallenge(string? existing)
    {
        ProtectedResourceChallenge.Compose(existing, Url)
            .Should().Be($"Bearer resource_metadata=\"{Url}\"");
    }

    [Fact]
    public void BareBearer_GainsTheParameterAfterASpace()
    {
        // This is the case that was silently dropped in production.
        ProtectedResourceChallenge.Compose("Bearer", Url)
            .Should().Be($"Bearer resource_metadata=\"{Url}\"");
    }

    [Fact]
    public void BareBearerWithTrailingSpace_IsNormalized()
    {
        ProtectedResourceChallenge.Compose("Bearer ", Url)
            .Should().Be($"Bearer resource_metadata=\"{Url}\"");
    }

    [Fact]
    public void ExistingParameters_GainTheParameterAfterAComma()
    {
        ProtectedResourceChallenge.Compose(
                "Bearer error=\"invalid_token\", error_description=\"expired\"", Url)
            .Should().Be(
                $"Bearer error=\"invalid_token\", error_description=\"expired\", resource_metadata=\"{Url}\"");
    }

    [Fact]
    public void AlreadyPresent_LeavesTheHeaderAlone()
    {
        // Null means "no change needed" — re-appending would produce a
        // duplicate parameter and an invalid challenge.
        ProtectedResourceChallenge.Compose($"Bearer resource_metadata=\"{Url}\"", Url)
            .Should().BeNull();
    }

    [Fact]
    public void AlreadyPresent_IsDetectedCaseInsensitively()
    {
        ProtectedResourceChallenge.Compose($"Bearer Resource_Metadata=\"{Url}\"", Url)
            .Should().BeNull();
    }
}
