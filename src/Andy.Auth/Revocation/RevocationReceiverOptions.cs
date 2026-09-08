namespace Andy.Auth.Revocation;

public sealed class RevocationReceiverOptions
{
    public string Authority { get; set; } = "";
    public string Audience { get; set; } = "";
    public TimeSpan Retention { get; set; } = TimeSpan.FromDays(31);
    public bool IsValid() => !string.IsNullOrWhiteSpace(Audience) && Audience.Length <= 256 &&
        Uri.TryCreate(Authority, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment) &&
        Retention >= TimeSpan.FromMinutes(5) && Retention <= TimeSpan.FromDays(365);
}
