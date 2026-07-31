using System.Security.Cryptography;
using System.Text;

namespace Andy.Auth.Server.Services;

/// <summary>
/// The tenant every token this deployment issues belongs to, and the only
/// source of the <c>tid</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// Tenancy in the Andy ecosystem is deployment-per-tenant: andy-tenants
/// describes itself as orchestrating "per-tenant deployments of andy-auth,
/// andy-rbac, andy-settings", andy-rbac discriminates identity realms on
/// <c>iss</c> (<c>RbacOptions.ProviderClaimType</c>), and this server's own
/// configuration calls itself "the current single-tenant product". A tenant is
/// therefore a property of the deployment, not of the user, the client, or the
/// request — and the deployment's stable public identity is already its
/// issuer, which every resource server pins.
/// </para>
/// <para>
/// Resource servers cannot act on that, because <c>iss</c> is a URI and a
/// tenant partition key is a GUID: andy-ahp keys row-level security, cache
/// namespaces, object keys, and quotas on one. So this projects the
/// deployment's identity into the shape those services need, from a value the
/// caller cannot reach.
/// </para>
/// <para>
/// Both sources are server-side. <c>Tenancy:TenantId</c> is an operator-chosen
/// GUID and wins when set; otherwise the id is derived deterministically from
/// <c>OpenIddict:Issuer</c>, which <c>Program.cs</c> refuses to start without
/// and which is fixed in configuration precisely so that it does not vary with
/// how the server was reached. Nothing in a token request, a client
/// registration, or an upstream identity provider's claims contributes to
/// either, which is what makes the claim unforgeable by a client that can
/// request its own token.
/// </para>
/// <para>
/// The derivation exists so that a deployment which never configures a tenant
/// still cannot collide with another one: distinct issuers derive distinct
/// ids. That is the failure this whole mechanism is about — an earlier
/// andy-ahp revision defaulted an absent tenant to <c>Guid.Empty</c>, which put
/// every such caller in one shared partition and made cross-tenant reads
/// possible. A deployment whose public URL will change before its data does
/// should pin <c>Tenancy:TenantId</c>, because the derived id moves with the
/// issuer.
/// </para>
/// </remarks>
public sealed class DeploymentTenant
{
    /// <summary>
    /// The claim name. Matches what andy-ahp's <c>AhpConnectionHandler</c> and
    /// <c>DedicatedTenantAdmission</c> read, and the name Entra uses for the
    /// same idea.
    /// </summary>
    public const string ClaimType = "tid";

    /// <summary>Configuration key holding an explicit tenant id.</summary>
    public const string ConfigurationKey = "Tenancy:TenantId";

    /// <summary>
    /// RFC 4122 namespace for andy-auth deployment tenants. Fixed forever: it
    /// is what makes the derived id reproducible across restarts and across
    /// machines, so two hosts serving the same issuer agree without sharing
    /// state.
    /// </summary>
    private static readonly Guid IssuerNamespace =
        new("6b4d9f2e-3a17-4c58-9e0d-1f7c2b845aa3");

    private DeploymentTenant(Guid tenantId, string source)
    {
        TenantId = tenantId;
        Source = source;
    }

    /// <summary>The tenant id carried by every token this deployment issues.</summary>
    public Guid TenantId { get; }

    /// <summary>
    /// Where <see cref="TenantId"/> came from, for the startup log. An operator
    /// diagnosing tenant-scoped data that went missing needs to know whether
    /// the id was pinned or derived.
    /// </summary>
    public string Source { get; }

    /// <summary>The claim value, in the form <see cref="Guid.TryParse"/> round-trips.</summary>
    public string ClaimValue => TenantId.ToString("D");

    public static DeploymentTenant Resolve(IConfiguration configuration)
    {
        var configured = configuration[ConfigurationKey];

        if (!string.IsNullOrWhiteSpace(configured))
        {
            // A configured-but-unusable value is a deployment mistake, and
            // falling back to the derived id would hide it: the operator would
            // get a working server issuing a tenant they did not choose, and
            // discover it only when tenant-scoped rows turned up under the
            // wrong partition.
            if (!Guid.TryParse(configured, out var explicitTenant) || explicitTenant == Guid.Empty)
            {
                throw new InvalidOperationException(
                    $"{ConfigurationKey} must be a non-empty GUID. " +
                    $"It was '{configured}'. Leave it unset to derive the tenant " +
                    "from OpenIddict:Issuer instead.");
            }

            return new DeploymentTenant(explicitTenant, ConfigurationKey);
        }

        var issuer = configuration["OpenIddict:Issuer"];

        if (string.IsNullOrWhiteSpace(issuer))
        {
            // Unreachable through Program.cs, which throws on an unset issuer
            // before this runs. Stated anyway so that a future caller which
            // resolves the tenant earlier fails loudly rather than deriving an
            // id from an empty string — every such deployment would share it.
            throw new InvalidOperationException(
                $"Neither {ConfigurationKey} nor OpenIddict:Issuer is configured, " +
                "so this deployment has no tenant identity to issue.");
        }

        return new DeploymentTenant(DeriveFromIssuer(issuer), "OpenIddict:Issuer");
    }

    /// <summary>
    /// The RFC 4122 §4.3 name-based UUID (version 5) of the issuer in
    /// <see cref="IssuerNamespace"/>.
    /// </summary>
    /// <remarks>
    /// The issuer is normalized to lower case with any trailing slash removed
    /// so that the same deployment written two ways in configuration does not
    /// split into two tenants. SHA-1 is what version 5 specifies; nothing here
    /// rests on its collision resistance, because the derivation is a naming
    /// convention over a value the caller never supplies rather than a
    /// security check.
    /// </remarks>
    public static Guid DeriveFromIssuer(string issuer)
    {
        var normalized = issuer.Trim().TrimEnd('/').ToLowerInvariant();

        var namespaceBytes = IssuerNamespace.ToByteArray();
        SwapToRfcByteOrder(namespaceBytes);

        var nameBytes = Encoding.UTF8.GetBytes(normalized);
        var input = new byte[namespaceBytes.Length + nameBytes.Length];
        namespaceBytes.CopyTo(input, 0);
        nameBytes.CopyTo(input, namespaceBytes.Length);

        var hash = SHA1.HashData(input);

        var derived = new byte[16];
        Array.Copy(hash, derived, 16);
        derived[6] = (byte)((derived[6] & 0x0F) | 0x50);
        derived[8] = (byte)((derived[8] & 0x3F) | 0x80);

        SwapToRfcByteOrder(derived);

        return new Guid(derived);
    }

    /// <summary>
    /// Converts between .NET's mixed-endian GUID layout and RFC 4122's
    /// big-endian one. The conversion is its own inverse.
    /// </summary>
    private static void SwapToRfcByteOrder(byte[] guid)
    {
        (guid[0], guid[3]) = (guid[3], guid[0]);
        (guid[1], guid[2]) = (guid[2], guid[1]);
        (guid[4], guid[5]) = (guid[5], guid[4]);
        (guid[6], guid[7]) = (guid[7], guid[6]);
    }
}
