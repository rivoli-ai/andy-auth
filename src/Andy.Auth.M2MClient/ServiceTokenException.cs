// Copyright (c) Rivoli AI 2026. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Andy.Auth.M2MClient;

/// <summary>
/// Raised when a service token cannot be acquired from the OAuth2
/// token endpoint. The <c>Message</c> is prefixed with a stable
/// greppable code so failure sites are easy to triage from logs:
/// <list type="bullet">
///   <item><c>[M2M-TOKEN-UNREACHABLE]</c> — token endpoint connection failed.</item>
///   <item><c>[M2M-TOKEN-REJECTED]</c>    — token endpoint returned a non-2xx status.</item>
///   <item><c>[M2M-TOKEN-EMPTY]</c>       — token endpoint returned 200 but no <c>access_token</c>.</item>
///   <item><c>[M2M-TOKEN-NOCLIENTID]</c>  — AndyAuth.ClientId is not configured.</item>
///   <item><c>[M2M-TOKEN-NOSECRETENV]</c> — AndyAuth.ClientSecretEnvVar is not configured.</item>
/// </list>
/// </summary>
public sealed class ServiceTokenException : Exception
{
    public ServiceTokenException(string message) : base(message) { }
    public ServiceTokenException(string message, Exception inner) : base(message, inner) { }
}
