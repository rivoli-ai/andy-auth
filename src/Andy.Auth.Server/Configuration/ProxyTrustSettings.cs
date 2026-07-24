using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
using IPNetwork = Microsoft.AspNetCore.HttpOverrides.IPNetwork;

namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Which upstream peers are allowed to set <c>X-Forwarded-For</c> /
/// <c>X-Forwarded-Proto</c> on a request.
/// </summary>
/// <remarks>
/// <para>
/// andy-auth#125. Startup used to call <c>KnownNetworks.Clear()</c> and
/// <c>KnownProxies.Clear()</c> unconditionally, which tells ASP.NET Core to
/// accept forwarding headers from <em>any</em> peer. Behind a proxy that
/// appends rather than overwrites — or on any direct-access path — a caller
/// could then choose the IP the server saw. That IP is what the rate limiter
/// keys on, what account lockout is attributed to, and what lands in audit
/// records, so login and token limits could be evaded by rotating a header
/// value.
/// </para>
/// <para>
/// The trust boundary is now an explicit, per-deployment decision rather than
/// a hidden default. Configure exactly one of:
/// <list type="bullet">
/// <item><c>KnownProxies</c> / <c>KnownNetworks</c> — the tightest option, for
/// deployments with stable proxy addressing.</item>
/// <item><c>TrustAllProxies</c> — for managed platforms (Railway et al.) whose
/// edge is contractually guaranteed to append the real client IP. Logged
/// loudly at startup because it is only sound under that contract.</item>
/// <item>Neither — ASP.NET Core's default, which trusts loopback only. Correct
/// for local development and Conductor's embedded mode, where the proxy runs
/// on localhost.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class ProxyTrustSettings
{
    public const string SectionName = "ForwardedHeaders";

    /// <summary>Individual proxy IP addresses permitted to forward.</summary>
    public string[] KnownProxies { get; set; } = Array.Empty<string>();

    /// <summary>Proxy networks in CIDR form (e.g. <c>10.0.0.0/8</c>).</summary>
    public string[] KnownNetworks { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Accept forwarding headers from any peer. Only sound when the edge
    /// overwrites or appends inbound <c>X-Forwarded-For</c>, so a client
    /// cannot choose its own apparent address.
    /// </summary>
    public bool TrustAllProxies { get; set; }

    /// <summary>
    /// How many proxy hops to walk back through. One means "the address the
    /// edge appended", which is the true client under an appending edge.
    /// Raising it trusts entries the client may have supplied.
    /// </summary>
    public int ForwardLimit { get; set; } = 1;

    /// <summary>
    /// Applies this configuration, returning a one-line description of the
    /// resulting trust boundary for the startup log.
    /// </summary>
    public string Apply(ForwardedHeadersOptions options)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = ForwardLimit;

        if (TrustAllProxies)
        {
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
            return "any peer (TrustAllProxies=true) — the edge MUST overwrite or append " +
                   "inbound X-Forwarded-For, or clients can spoof their address";
        }

        if (KnownProxies.Length == 0 && KnownNetworks.Length == 0)
        {
            // Leave the framework defaults in place: loopback only.
            return "loopback only (ASP.NET Core default; no ForwardedHeaders trust configured)";
        }

        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();

        foreach (var proxy in KnownProxies)
        {
            if (!IPAddress.TryParse(proxy, out var address))
            {
                throw new InvalidOperationException(
                    $"ForwardedHeaders:KnownProxies contains '{proxy}', which is not a valid IP address.");
            }
            options.KnownProxies.Add(address);
        }

        foreach (var network in KnownNetworks)
        {
            options.KnownNetworks.Add(ParseCidr(network));
        }

        return $"{options.KnownProxies.Count} proxy address(es), {options.KnownNetworks.Count} network(s)";
    }

    private static IPNetwork ParseCidr(string value)
    {
        var parts = value.Split('/', 2);
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var prefix) ||
            !int.TryParse(parts[1], out var prefixLength))
        {
            throw new InvalidOperationException(
                $"ForwardedHeaders:KnownNetworks contains '{value}', which is not valid CIDR notation " +
                "(e.g. \"10.0.0.0/8\").");
        }

        var maxPrefixLength = prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        if (prefixLength < 0 || prefixLength > maxPrefixLength)
        {
            throw new InvalidOperationException(
                $"ForwardedHeaders:KnownNetworks contains '{value}', whose prefix length is out of range " +
                $"for the address family (0-{maxPrefixLength}).");
        }

        return new IPNetwork(prefix, prefixLength);
    }
}
