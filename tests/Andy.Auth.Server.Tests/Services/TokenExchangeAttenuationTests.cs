using Andy.Auth.Server.Services;
using FluentAssertions;

namespace Andy.Auth.Server.Tests.Services;

public sealed class TokenExchangeAttenuationTests
{
    [Fact]
    public void HasTrustedAudience_RejectsUnrelatedAndEmptyTrustSets()
    {
        TokenExchangeAttenuation.HasTrustedAudience(
                new[] { "urn:unrelated-api" },
                new[] { "urn:actor-api" })
            .Should().BeFalse();
        TokenExchangeAttenuation.HasTrustedAudience(
                new[] { "urn:actor-api" },
                Array.Empty<string>())
            .Should().BeFalse();
    }

    [Fact]
    public void HasTrustedAudience_AcceptsExactConfiguredSource()
    {
        TokenExchangeAttenuation.HasTrustedAudience(
                new[] { "urn:actor-api" },
                new[] { "urn:actor-api" })
            .Should().BeTrue();
    }

    [Fact]
    public void AttenuateScopes_CannotAddScopeAbsentFromSubject()
    {
        var result = TokenExchangeAttenuation.AttenuateScopes(
            new[] { "read" },
            new[] { "read", "admin" },
            new[] { "admin" });

        result.IsAllowed.Should().BeFalse();
        result.DisallowedScopes.Should().ContainSingle("admin");
    }

    [Fact]
    public void AttenuateScopes_IntersectsSubjectPolicyAndRequest()
    {
        var result = TokenExchangeAttenuation.AttenuateScopes(
            new[] { "read", "write", "profile" },
            new[] { "read", "profile" },
            new[] { "read" });

        result.IsAllowed.Should().BeTrue();
        result.EffectiveScopes.Should().ContainSingle("read");
    }

    [Fact]
    public void AttenuateScopes_NoRequest_UsesSubjectPolicyIntersection()
    {
        var result = TokenExchangeAttenuation.AttenuateScopes(
            new[] { "read", "write" },
            new[] { "read" },
            Array.Empty<string>());

        result.IsAllowed.Should().BeTrue();
        result.EffectiveScopes.Should().BeEquivalentTo("read");
    }

    [Fact]
    public void CapLifetime_UsesConfiguredMaximumWhenSubjectLivesLonger()
    {
        var now = DateTimeOffset.UtcNow;

        var result = TokenExchangeAttenuation.CapLifetime(
            now.AddHours(1), now, TimeSpan.FromMinutes(15));

        result.Should().Be(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void CapLifetime_UsesSubjectRemainderWhenShorter()
    {
        var now = DateTimeOffset.UtcNow;

        var result = TokenExchangeAttenuation.CapLifetime(
            now.AddMinutes(3), now, TimeSpan.FromMinutes(15));

        result.Should().Be(TimeSpan.FromMinutes(3));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void CapLifetime_RejectsExpiredSubject(int offsetSeconds)
    {
        var now = DateTimeOffset.UtcNow;

        TokenExchangeAttenuation.CapLifetime(
                now.AddSeconds(offsetSeconds), now, TimeSpan.FromMinutes(15))
            .Should().BeNull();
    }
}
