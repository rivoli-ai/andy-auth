using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Models.Dcr;

public sealed class RegistrationAccessTokenRotationResponse
{
    [JsonPropertyName("registration_access_token")]
    public string RegistrationAccessToken { get; init; } = string.Empty;

    [JsonPropertyName("registration_access_token_expires_at")]
    public long? ExpiresAt { get; init; }
}
