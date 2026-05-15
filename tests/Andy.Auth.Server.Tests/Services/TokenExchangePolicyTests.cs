using Andy.Auth.Server.Configuration;
using Andy.Auth.Server.Services;
using Microsoft.Extensions.Options;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// Unit coverage for <see cref="TokenExchangePolicy"/>. The policy is
/// pure config-binding logic so these tests don't need a host or DB.
/// Drives Epic IDP (rivoli-ai/conductor#1246).
/// </summary>
public class TokenExchangePolicyTests
{
    private static TokenExchangePolicy MakePolicy(TokenExchangeSettings settings) =>
        new(Options.Create(settings));

    [Fact]
    public void IsAllowed_ReturnsTrue_WhenActorAndAudienceMatch()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.True(policy.IsAllowed("andy-containers-api", "urn:andy-models-api"));
    }

    [Fact]
    public void IsAllowed_IsCaseInsensitiveOnActorClientId()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.True(policy.IsAllowed("ANDY-CONTAINERS-API", "urn:andy-models-api"));
    }

    [Fact]
    public void IsAllowed_IsCaseSensitiveOnAudience()
    {
        // Audiences are URNs and are case-sensitive per RFC 8141.
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.False(policy.IsAllowed("andy-containers-api", "URN:ANDY-MODELS-API"));
    }

    [Fact]
    public void IsAllowed_ReturnsFalse_WhenAudienceNotOnList()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.False(policy.IsAllowed("andy-containers-api", "urn:andy-rbac-api"));
    }

    [Fact]
    public void IsAllowed_ReturnsFalse_WhenActorNotOnList()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.False(policy.IsAllowed("untrusted-service", "urn:andy-models-api"));
    }

    [Fact]
    public void IsAllowed_ReturnsFalse_WhenFeatureDisabled()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = false,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.False(policy.IsAllowed("andy-containers-api", "urn:andy-models-api"));
    }

    [Fact]
    public void IsAllowed_ReturnsFalse_OnEmptyArguments()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                },
            },
        });

        Assert.False(policy.IsAllowed("", "urn:andy-models-api"));
        Assert.False(policy.IsAllowed("andy-containers-api", ""));
        Assert.False(policy.IsAllowed("", ""));
    }

    [Fact]
    public void AllowedScopes_ReturnsEntryScopes_WhenSpecified()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new()
            {
                new TokenExchangePolicyEntry
                {
                    ActorClientId = "andy-containers-api",
                    Audience = "urn:andy-models-api",
                    AllowedScopes = new() { "models.read", "models.invoke" },
                },
            },
        });

        var scopes = policy.AllowedScopes("andy-containers-api", "urn:andy-models-api");
        Assert.Equal(new[] { "models.read", "models.invoke" }, scopes);
    }

    [Fact]
    public void AllowedScopes_ReturnsEmpty_WhenNoEntryMatched()
    {
        var policy = MakePolicy(new TokenExchangeSettings
        {
            Enabled = true,
            Policies = new(),
        });

        Assert.Empty(policy.AllowedScopes("any", "any"));
    }
}
