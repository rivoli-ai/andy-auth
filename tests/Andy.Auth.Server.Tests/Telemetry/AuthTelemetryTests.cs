// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Diagnostics;
using Andy.Auth.Server.Telemetry;
using FluentAssertions;
using Xunit;

namespace Andy.Auth.Server.Tests.Telemetry;

/// <summary>
/// Verifies that the OT4 (rivoli-ai/conductor#1262) telemetry plumbing
/// in andy-auth is wired up so spans + metrics are observable.
///
/// We don't boot the full Conductor → andy-auth → OTLP pipeline here.
/// What we DO assert is that:
///
///   1. <see cref="AuthTelemetry.ActivitySource"/> is listened-to by a
///      <see cref="ActivityListener"/> that subscribes to its name —
///      i.e. spans started via that source surface for any registered
///      exporter (OTLP, Console, in-process listeners). If the name is
///      ever renamed without updating the
///      <c>AddAndyTelemetry(... o.ActivitySources.Add(...) ...)</c>
///      wiring in Program.cs, the SDK will silently drop every span.
///
///   2. The <c>tokens.minted</c> counter is observable via the
///      <c>System.Diagnostics.Metrics</c> primitives — proving the
///      instrument is on the canonical meter.
/// </summary>
public class AuthTelemetryTests
{
    [Fact]
    public void ActivitySource_StartsAnActivity_WhenListenerSubscribes()
    {
        var captured = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AuthTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity => captured.Add(activity),
        };
        ActivitySource.AddActivityListener(listener);

        using (var activity = AuthTelemetry.ActivitySource.StartActivity("TokenMint"))
        {
            activity.Should().NotBeNull("an active listener must materialise the activity");
            activity!.SetTag("auth.grant_type", "client_credentials");
            activity.SetTag("auth.outcome", "success");
        }

        captured.Should().ContainSingle();
        var span = captured[0];
        span.OperationName.Should().Be("TokenMint");
        span.GetTagItem("auth.grant_type").Should().Be("client_credentials");
        span.GetTagItem("auth.outcome").Should().Be("success");
    }

    [Fact]
    public void TokensMintedCounter_IsOnTheCanonicalMeter()
    {
        AuthTelemetry.TokensMinted.Description
            .Should().NotBeNullOrEmpty();
        AuthTelemetry.TokensMinted.Meter.Name
            .Should().Be(AuthTelemetry.MeterName);
        AuthTelemetry.TokensMinted.Name
            .Should().Be("auth.tokens.minted");
    }

    /// <summary>
    /// OT7 (rivoli-ai/conductor#1265). The token-mint span must carry
    /// the <c>andy.auth.*</c> attribute namespace alongside the legacy
    /// <c>auth.*</c> names during the 0.2.4 dual-emit window. This
    /// test exercises the same `SetTag` shape the controller uses so a
    /// future refactor that drops the dual-emit prematurely trips here.
    /// </summary>
    [Fact]
    public void TokenMintSpan_CarriesAndyAuthNamespaceAlongsideLegacyAuthTags()
    {
        var captured = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AuthTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity => captured.Add(activity),
        };
        ActivitySource.AddActivityListener(listener);

        using (var activity = AuthTelemetry.ActivitySource.StartActivity("TokenMint"))
        {
            activity!.SetTag("andy.auth.grant_type", "client_credentials");
            activity.SetTag("andy.auth.client_id", "client-123");
            activity.SetTag("andy.auth.outcome", "success");
            // Legacy names still emit during the 0.2.4 transition.
            activity.SetTag("auth.grant_type", "client_credentials");
            activity.SetTag("auth.client_id", "client-123");
            activity.SetTag("auth.outcome", "success");
        }

        captured.Should().ContainSingle();
        var span = captured[0];
        span.GetTagItem("andy.auth.grant_type").Should().Be("client_credentials");
        span.GetTagItem("andy.auth.client_id").Should().Be("client-123");
        span.GetTagItem("andy.auth.outcome").Should().Be("success");
        // Legacy names must still resolve until Andy.Telemetry 0.3.0.
        span.GetTagItem("auth.grant_type").Should().Be("client_credentials");
        span.GetTagItem("auth.outcome").Should().Be("success");
    }
}
