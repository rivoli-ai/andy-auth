using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Andy.Auth.Server.Configuration;

public static class ForwardedProxyTrust
{
    public static void Configure(ForwardedHeadersOptions options, IConfiguration config, bool hardened)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        var limit = config.GetValue("ForwardLimit", 1);
        if (limit < 1) throw new InvalidOperationException("ForwardedHeaders:ForwardLimit must be positive.");
        options.ForwardLimit = limit;
        if (config.GetValue("TrustAllProxies", false))
        {
            if (hardened) throw new InvalidOperationException("TrustAllProxies is prohibited outside local/embedded environments.");
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
            return;
        }

        // Validate every entry before mutating the trust set. Silently dropping
        // malformed entries after clearing it would accidentally trust everyone.
        var proxies = (config.GetSection("KnownProxies").Get<string[]>() ?? Array.Empty<string>())
            .Select(value => IPAddress.TryParse(value, out var address) ? address :
                throw new InvalidOperationException($"Invalid trusted proxy address: {value}")).ToArray();
        var networks = (config.GetSection("KnownNetworks").Get<string[]>() ?? Array.Empty<string>())
            .Select(value =>
            {
                var parts = value.Split('/', StringSplitOptions.TrimEntries);
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var prefix) ||
                    !int.TryParse(parts[1], out var length) || length < 1 ||
                    length > (prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))
                    throw new InvalidOperationException($"Invalid trusted proxy network: {value}");
                return new Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, length);
            }).ToArray();

        if (proxies.Length == 0 && networks.Length == 0) return; // retain loopback-only framework defaults
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
        foreach (var proxy in proxies) options.KnownProxies.Add(proxy);
        foreach (var network in networks) options.KnownNetworks.Add(network);
    }
}
