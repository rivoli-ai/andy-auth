using Microsoft.AspNetCore.Http.Metadata;

namespace Andy.Auth.Server.Controllers;

/// <summary>
/// Restores the cookie handler's redirect-to-login for a single action on an
/// <c>[ApiController]</c>.
/// </summary>
/// <remarks>
/// <para>
/// .NET 10 stopped redirecting unauthenticated cookie challenges to
/// <c>LoginPath</c> for endpoints it classifies as APIs, returning 401 (with a
/// <c>Location</c> header) instead:
/// https://learn.microsoft.com/aspnet/core/breaking-changes/10/cookie-authentication-api-endpoints
/// </para>
/// <para>
/// Classification is by endpoint metadata, not request headers:
/// <c>ApiControllerAttribute</c> implements <c>IDisableCookieRedirectMetadata</c>,
/// and <c>CookieAuthenticationEvents</c> suppresses the redirect when that
/// metadata is present and <c>IAllowCookieRedirectMetadata</c> is not. Applying
/// this attribute to an action puts the latter back on the endpoint.
/// </para>
/// <para>
/// Prefer this over overriding <c>OnRedirectToLogin</c>: the application cookie
/// sets <c>EventsType</c> (see <see cref="Services.InteractiveSessionCookieEvents"/>),
/// and a handler resolves events from <c>EventsType</c> *or* <c>Options.Events</c>
/// — never both — so assigning <c>options.Events.OnRedirectToLogin</c> in
/// <c>ConfigureApplicationCookie</c> would silently never run. Endpoint metadata
/// also travels with the controller, so the E2E host in
/// <c>tests/Andy.Auth.E2E.Tests/E2ETestServer.cs</c>, which mirrors rather than
/// reuses <c>Program.cs</c>, cannot drift away from production behaviour here.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true)]
public sealed class AllowCookieRedirectAttribute : Attribute, IAllowCookieRedirectMetadata
{
}
