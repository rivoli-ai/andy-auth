namespace Andy.Auth.Server.Data;

public sealed class CibaAuthentication
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string RequestHash { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string Scope { get; set; } = "";
    public string BindingMessage { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime NextPollAtUtc { get; set; }
    public int PollIntervalSeconds { get; set; }
    public string Status { get; set; } = "pending";
    public string? SessionId { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public bool UsedMfa { get; set; }
    public string? SecurityStampHash { get; set; }
    public DateTime NextPushAtUtc { get; set; }
    public DateTime? PushLeaseUntilUtc { get; set; }
    public string? PushLease { get; set; }
    public bool PushDelivered { get; set; }
    public int PushAttempts { get; set; }
}

/// <summary>One explicitly enrolled authentication device per user; secrets protected by Data Protection.</summary>
public sealed class CibaPushDevice
{
    public string UserId { get; set; } = "";
    public string EndpointHash { get; set; } = "";
    public string ProtectedSubscription { get; set; } = "";
    public DateTime RegisteredAtUtc { get; set; }
}
