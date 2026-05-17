// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Andy.Auth.Server.Telemetry;

/// <summary>
/// Domain <see cref="ActivitySource"/> and <see cref="Meter"/> for andy-auth.
///
/// Wired via Andy.Telemetry in <c>Program.cs</c> (see OT4 —
/// rivoli-ai/conductor#1262). Use <see cref="ActivitySource"/> to emit
/// spans around token mint / OIDC authorize / introspect operations,
/// and <see cref="Meter"/> for domain counters / histograms.
/// </summary>
public static class AuthTelemetry
{
    /// <summary>
    /// Activity source name. Matches the registration in
    /// <c>AddAndyTelemetry(... o.ActivitySources.Add(...) ...)</c>.
    /// </summary>
    public const string ActivitySourceName = "Andy.Auth";

    /// <summary>
    /// Meter name. Matches the registration in
    /// <c>AddAndyTelemetry(... o.Meters.Add(...) ...)</c>.
    /// </summary>
    public const string MeterName = "Andy.Auth";

    /// <summary>
    /// Activity source for spans emitted by andy-auth (token mint, OIDC
    /// authorize, RFC 8693 token exchange, MFA challenge, ...).
    /// </summary>
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName);

    /// <summary>
    /// Meter for andy-auth domain metrics (token mint count, exchange
    /// count, failure counters by reason, ...).
    /// </summary>
    public static readonly Meter Meter = new(MeterName);

    /// <summary>
    /// Count of tokens minted by grant type. Tagged with
    /// <c>auth.grant_type</c> (authorization_code, refresh_token,
    /// client_credentials, device_code, token-exchange) and
    /// <c>auth.outcome</c> (success, failure).
    /// </summary>
    public static readonly Counter<long> TokensMinted =
        Meter.CreateCounter<long>(
            name: "auth.tokens.minted",
            unit: "{token}",
            description: "Count of tokens minted by andy-auth, tagged by grant type and outcome.");
}
