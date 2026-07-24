using Andy.Auth.Server.Services;
using FluentAssertions;
using Xunit;

namespace Andy.Auth.Server.Tests.Services;

/// <summary>
/// andy-auth#124. The consent screen used to signal approval with
/// <c>consent_granted=true</c> on the return URL, which
/// <c>AuthorizationController.Authorize</c> trusted. The authorization request
/// is client-controlled, so anyone could append that themselves — or hand a
/// victim a link with it already set — and never see a consent screen.
/// These lock the properties the replacement has to hold.
/// </summary>
public class ConsentTicketServiceTests
{
    private static ConsentTicketService Create() => TestConsent.CreateConsentTicketService();

    private const string User = "user-1";
    private const string Client = "test-client";
    private const string Redirect = "https://client.example/callback";

    [Fact]
    public void Redeem_ReturnsTheApprovedScopes_ForAMatchingRequest()
    {
        var service = Create();
        var ticket = service.Issue(User, Client, Redirect, new[] { "openid", "profile" });

        var scopes = service.Redeem(ticket, User, Client, Redirect);

        scopes.Should().BeEquivalentTo("openid", "profile");
    }

    [Fact]
    public void Redeem_RejectsAnAbsentTicket()
    {
        // The whole point: no ticket, no consent. There is no longer any
        // caller-supplied value that stands in for approval.
        Create().Redeem(null, User, Client, Redirect).Should().BeNull();
        Create().Redeem("", User, Client, Redirect).Should().BeNull();
    }

    [Fact]
    public void Redeem_RejectsAForgedTicket()
    {
        Create().Redeem("consent_granted=true", User, Client, Redirect).Should().BeNull();
        Create().Redeem("true", User, Client, Redirect).Should().BeNull();
    }

    [Fact]
    public void Redeem_RejectsATicketIssuedToAnotherUser()
    {
        var service = Create();
        var ticket = service.Issue("someone-else", Client, Redirect, new[] { "openid" });

        service.Redeem(ticket, User, Client, Redirect).Should().BeNull();
    }

    [Fact]
    public void Redeem_RejectsATicketIssuedForAnotherClient()
    {
        // Without this binding, consent granted to a benign client would
        // authorize a hostile one.
        var service = Create();
        var ticket = service.Issue(User, "benign-client", Redirect, new[] { "openid" });

        service.Redeem(ticket, User, "hostile-client", Redirect).Should().BeNull();
    }

    [Fact]
    public void Redeem_RejectsATicketBoundToAnotherRedirectUri()
    {
        // Without this binding, consent would authorize delivery of the
        // authorization code somewhere the user never saw.
        var service = Create();
        var ticket = service.Issue(User, Client, Redirect, new[] { "openid" });

        service.Redeem(ticket, User, Client, "https://attacker.example/callback")
            .Should().BeNull();
    }

    [Fact]
    public void Redeem_RejectsATamperedTicket()
    {
        var service = Create();
        var ticket = service.Issue(User, Client, Redirect, new[] { "openid" });
        var tampered = ticket[..^4] + "AAAA";

        service.Redeem(tampered, User, Client, Redirect).Should().BeNull();
    }

    [Fact]
    public void Redeem_CannotBeWidenedBeyondTheApprovedScopes()
    {
        // A partial approval must stay partial — the ticket is the only source
        // of the granted set, and it is authenticated.
        var service = Create();
        var ticket = service.Issue(User, Client, Redirect, new[] { "openid" });

        service.Redeem(ticket, User, Client, Redirect)
            .Should().BeEquivalentTo("openid");
    }

    [Fact]
    public void Issue_RoundTripsScopesContainingNoSeparatorCollision()
    {
        // Scope values are URI-ish for resource scopes; make sure the field
        // packing survives them.
        var service = Create();
        var scopes = new[] { "openid", "urn:andy-docs-api", "https://localhost:5101/mcp" };
        var ticket = service.Issue(User, Client, Redirect, scopes);

        service.Redeem(ticket, User, Client, Redirect).Should().BeEquivalentTo(scopes);
    }

    [Fact]
    public void Redeem_TreatsNullAndEmptyRedirectUriAsEquivalent()
    {
        // OpenIddict leaves RedirectUri null when the client registered exactly
        // one; the ticket must still line up.
        var service = Create();
        var ticket = service.Issue(User, Client, null, new[] { "openid" });

        service.Redeem(ticket, User, Client, null).Should().BeEquivalentTo("openid");
    }
}
