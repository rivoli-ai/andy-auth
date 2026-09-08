namespace Andy.Auth.Server.Services.Revocation;

public sealed class RevocationDeliveryOptions
{
    public bool Enabled { get; set; }
    public List<RevocationRecipient> Targets { get; set; } = new();

    public bool IsValid() => !Enabled || Targets.Count > 0 &&
        Targets.Select(target => target.Audience).Distinct(StringComparer.Ordinal).Count() == Targets.Count &&
        Targets.All(target => !string.IsNullOrWhiteSpace(target.Audience) && target.Audience.Length <= 256 &&
            Uri.TryCreate(target.Endpoint, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
            string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment));
}

public sealed class RevocationRecipient
{
    public string Audience { get; set; } = "";
    public string Endpoint { get; set; } = "";
}
