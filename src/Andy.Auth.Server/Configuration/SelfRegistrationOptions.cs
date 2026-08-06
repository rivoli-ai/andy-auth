namespace Andy.Auth.Server.Configuration;

/// <summary>
/// Controls public, password-based account creation. Disabled by default so an
/// internal deployment cannot expose registration by omitting configuration.
/// </summary>
public sealed class SelfRegistrationOptions
{
    public const string SectionName = "SelfRegistration";

    public bool Enabled { get; set; }

    /// <summary>
    /// Requires a confirmed address before a local account may sign in.
    /// Keep enabled whenever self-registration is exposed.
    /// </summary>
    public bool RequireConfirmedEmail { get; set; } = true;
}
