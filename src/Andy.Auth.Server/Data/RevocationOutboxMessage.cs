namespace Andy.Auth.Server.Data;

/// <summary>No user/session FK: notifications must survive account deletion.</summary>
public sealed class RevocationOutboxMessage
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string Recipient { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime NextAttemptAtUtc { get; set; }
    public DateTime? LeaseUntilUtc { get; set; }
    public string? LeaseToken { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
}
