using System.Net;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Andy.Auth.Server.Configuration;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Andy.Auth.Server.Tests;

// Pins andy-auth#128: a nonce-based Content-Security-Policy is enabled by
// default in Production and UAT, stays restrictive on the document-level
// directives, and is compatible with the Razor views (the per-request nonce is
// wired into the header AND the rendered inline <style>/<script> elements).
public class CspHeaderTests : IDisposable
{
    private readonly string _baseTemp;

    public CspHeaderTests()
    {
        _baseTemp = Path.Combine(
            Path.GetTempPath(),
            "andy-auth-csp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_baseTemp);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_baseTemp))
            {
                Directory.Delete(_baseTemp, recursive: true);
            }
        }
        catch (IOException) { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Csp_EnabledByDefaultInProduction_WithRestrictiveDirectives()
    {
        using var factory = CreateFactory("Production", keysPath: NewDir("keys"),
            issuer: "https://auth.example.test/");
        using var client = Client(factory, https: true);

        var response = await client.GetAsync("/health");
        var csp = GetCsp(response);

        csp.Should().NotBeNull("Production must enable CSP by default (#128)");
        AssertRestrictiveDirectives(csp!);
        csp!.Should().MatchRegex(@"script-src [^;]*'nonce-",
            "script-src must carry a per-request nonce, not 'unsafe-inline'");
        Regex.Match(csp!, @"script-src ([^;]*)").Groups[1].Value
            .Should().NotContain("'unsafe-inline'",
                "script-src must not fall back to 'unsafe-inline' (that would defeat the nonce)");
    }

    [Fact]
    public async Task Csp_EnabledByDefaultInUat()
    {
        using var factory = CreateFactory("UAT", issuer: "https://auth-uat.example.test/");
        using var client = Client(factory, https: false); // UAT disables transport security

        var response = await client.GetAsync("/health");
        var csp = GetCsp(response);

        csp.Should().NotBeNull("UAT must enable CSP by default (#128)");
        AssertRestrictiveDirectives(csp!);
    }

    [Fact]
    public async Task Csp_DisabledByDefaultInDevelopment()
    {
        // Guards the default: Development keeps CSP off so iteration isn't
        // blocked; the header must be absent unless explicitly enabled.
        using var factory = CreateFactory("Development");
        using var client = Client(factory, https: false);

        var response = await client.GetAsync("/health");

        GetCsp(response).Should().BeNull("Development leaves CSP off by default");
    }

    [Fact]
    public async Task Csp_NonceIsWiredIntoLoginView()
    {
        // End-to-end: the nonce in the CSP header must match the nonce stamped
        // onto the inline <style>/<script> elements of the rendered login page,
        // so the sign-in flow actually works under the policy.
        using var factory = CreateFactory(HostEnvironmentExtensions.EmbeddedEnvironmentName,
            keysPath: NewDir("keys"),
            extra: new[] { new KeyValuePair<string, string?>("SecurityHeaders__EnableCsp", "true") });
        using var client = Client(factory, https: false);

        var response = await client.GetAsync("/Account/Login");
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the login page must render under CSP");

        var csp = GetCsp(response);
        csp.Should().NotBeNull();

        var headerNonce = Regex.Match(csp!, @"'nonce-([^']+)'").Groups[1].Value;
        headerNonce.Should().NotBeNullOrEmpty("the CSP header must contain a nonce");

        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain($"nonce=\"{headerNonce}\"",
            "the per-request nonce must be stamped onto the view's inline <style>/<script> elements");
    }

    [Fact]
    public void AdminUsersView_EditName_DoesNotBuildInlineHandlerFromFullName()
    {
        // Regression guard for the CSP-review Major: because script-src-attr keeps
        // 'unsafe-inline', an inline onclick built from the attacker-controlled
        // FullName was a stored-XSS attribute breakout. The Edit-name control must
        // instead pass FullName via an auto-encoded data-* attribute and a delegated
        // addEventListener (no @Html.Raw, no inline handler). A full render test would
        // need admin auth + Postgres, so assert the source invariant directly.
        var viewPath = ResolveRepoFile("src/Andy.Auth.Server/Views/Admin/Users.cshtml");
        File.Exists(viewPath).Should().BeTrue($"expected the Users view at {viewPath}");

        var content = File.ReadAllText(viewPath);
        content.Should().NotContain("Html.Raw(user.FullName",
            "the FullName inline-handler XSS sink must not be reintroduced");
        content.Should().MatchRegex(@"data-current-name=""@\(user\.FullName",
            "Edit-name must carry FullName in an auto-encoded data-* attribute");
        content.Should().Contain(".js-edit-name",
            "Edit-name must use a delegated addEventListener handler, not inline onclick");
    }

    private static string ResolveRepoFile(string relativePath, [CallerFilePath] string testFilePath = "")
    {
        // CallerFilePath alone is not enough. Directory.Build.props sets
        // ContinuousIntegrationBuild under GITHUB_ACTIONS, which turns on
        // deterministic source-path mapping — so in CI this arrives as
        // "/_/tests/Andy.Auth.Server.Tests/CspHeaderTests.cs" and the file
        // never resolves. That is why this assertion passed locally and failed
        // on every CI run after central package management landed.
        //
        // Prefer the compile-time path when it actually exists (the local
        // developer case), otherwise walk up from the test binary looking for
        // the solution file.
        var testProjectDir = Path.GetDirectoryName(testFilePath);
        if (!string.IsNullOrEmpty(testProjectDir) && Directory.Exists(testProjectDir))
        {
            var mapped = Path.GetFullPath(Path.Combine(testProjectDir, "..", ".."));
            var candidate = Path.Combine(mapped, relativePath.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        var repoRoot = FindRepoRoot()
            ?? throw new InvalidOperationException(
                "Could not locate the repository root (no andy-auth.sln found walking up from " +
                $"{AppContext.BaseDirectory}).");

        return Path.Combine(repoRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>
    /// Walks up from the test assembly until it finds the directory holding
    /// andy-auth.sln. Independent of source-path mapping, so it works under a
    /// deterministic CI build.
    /// </summary>
    private static string? FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "andy-auth.sln")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        return null;
    }

    private static void AssertRestrictiveDirectives(string csp)
    {
        csp.Should().Contain("frame-ancestors 'none'");
        csp.Should().Contain("base-uri 'self'");
        csp.Should().Contain("object-src 'none'");
        csp.Should().Contain("form-action 'self'");
    }

    private static string? GetCsp(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Content-Security-Policy", out var values)
            ? values.FirstOrDefault()
            : null;

    private string NewDir(string name)
    {
        var dir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"), name);
        Directory.CreateDirectory(dir);
        return dir;
    }

    private EnvironmentWebApplicationFactory CreateFactory(
        string environmentName,
        string? keysPath = null,
        string? issuer = null,
        IEnumerable<KeyValuePair<string, string?>>? extra = null)
    {
        var modeDir = Path.Combine(_baseTemp, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(modeDir);

        return new EnvironmentWebApplicationFactory(
            environmentName: environmentName,
            dbPath: Path.Combine(modeDir, "andy-auth.sqlite"),
            issuer: issuer ?? "http://localhost:9100/auth/",
            keysPath: keysPath,
            extraEnvironment: extra);
    }

    private static HttpClient Client(WebApplicationFactory<Program> factory, bool https) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(https ? "https://localhost/" : "http://localhost/")
        });
}
