using System.Security.Cryptography;
using Microsoft.Playwright;

namespace Andy.Auth.E2E.Tests;

public sealed class AndyDocsWebSignInTests : E2ETestBase
{
    [Fact]
    public async Task BrowserSignIn_ReachesLocalPkceCallback()
    {
        await LoginAsAdminAsync();
        IRequest? callback = null;
        Page.Request += (_, request) =>
        {
            if (request.Url.StartsWith("http://localhost:4200/auth/callback?", StringComparison.Ordinal))
                callback = request;
        };
        var challenge = Convert.ToBase64String(SHA256.HashData(RandomNumberGenerator.GetBytes(32)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        try
        {
        await NavigateToAsync("/connect/authorize?client_id=andy-docs-web&response_type=code" +
            "&redirect_uri=http%3A%2F%2Flocalhost%3A4200%2Fauth%2Fcallback&scope=openid" +
            $"&state=docs-browser&code_challenge={challenge}&code_challenge_method=S256");
        }
        catch (PlaywrightException ex) when (callback is not null && ex.Message.Contains("ERR_CONNECTION_REFUSED"))
        {
            // The consumer SPA need not run for this auth-server test. Verify
            // that the real browser followed the server's redirect to it.
        }
        Assert.NotNull(callback);
        Assert.StartsWith("http://localhost:4200/auth/callback?", callback.Url);
        Assert.Contains("code=", callback.Url);
        Assert.Contains("state=docs-browser", callback.Url);
    }
}
