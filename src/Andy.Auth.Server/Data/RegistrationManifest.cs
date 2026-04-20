// Copyright (c) Rivoli AI 2026. All rights reserved.
using System.Text.Json.Serialization;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Wire format of config/registration.json files produced by the andy-service-template.
/// Every Andy ecosystem service ships one; andy-auth, andy-rbac, and andy-settings each
/// read their relevant section (auth / rbac / settings) on startup and seed from it.
///
/// Schema: ../../andy-service-template/docs/registration.schema.json
/// </summary>
public sealed record RegistrationManifest(
    [property: JsonPropertyName("service")]  RegistrationServiceInfo Service,
    [property: JsonPropertyName("auth")]     RegistrationAuthInfo?   Auth,
    [property: JsonPropertyName("rbac")]     RegistrationRbacInfo?   Rbac,
    [property: JsonPropertyName("settings")] RegistrationSettingsInfo? Settings
);

public sealed record RegistrationServiceInfo(
    [property: JsonPropertyName("name")]                string Name,
    [property: JsonPropertyName("displayName")]         string DisplayName,
    [property: JsonPropertyName("description")]         string Description,
    [property: JsonPropertyName("embeddedProxyPrefix")] string EmbeddedProxyPrefix,
    [property: JsonPropertyName("ports")]               RegistrationPorts? Ports
);

public sealed record RegistrationPorts(
    [property: JsonPropertyName("dotnetHttps")]    int DotnetHttps,
    [property: JsonPropertyName("dotnetHttp")]     int DotnetHttp,
    [property: JsonPropertyName("dotnetPostgres")] int DotnetPostgres,
    [property: JsonPropertyName("dotnetClient")]   int? DotnetClient,
    [property: JsonPropertyName("dockerHttps")]    int DockerHttps,
    [property: JsonPropertyName("dockerHttp")]     int DockerHttp,
    [property: JsonPropertyName("dockerPostgres")] int DockerPostgres,
    [property: JsonPropertyName("dockerClient")]   int? DockerClient,
    [property: JsonPropertyName("embeddedProxy")]  int EmbeddedProxy
);

public sealed record RegistrationAuthInfo(
    [property: JsonPropertyName("audience")]       string Audience,
    [property: JsonPropertyName("apiClient")]      RegistrationOAuthClient? ApiClient,
    [property: JsonPropertyName("webClient")]      RegistrationOAuthClient? WebClient,
    [property: JsonPropertyName("cliClient")]      RegistrationOAuthClient? CliClient,
    [property: JsonPropertyName("productionUris")] RegistrationProductionUris? ProductionUris
);

public sealed record RegistrationOAuthClient(
    [property: JsonPropertyName("clientId")]               string ClientId,
    [property: JsonPropertyName("clientType")]             string? ClientType,
    [property: JsonPropertyName("clientSecretEnvVar")]     string? ClientSecretEnvVar,
    [property: JsonPropertyName("displayName")]            string DisplayName,
    [property: JsonPropertyName("description")]            string? Description,
    [property: JsonPropertyName("grantTypes")]             string[]? GrantTypes,
    [property: JsonPropertyName("scopes")]                 string[]? Scopes,
    [property: JsonPropertyName("redirectUris")]           string[]? RedirectUris,
    [property: JsonPropertyName("postLogoutRedirectUris")] string[]? PostLogoutRedirectUris
);

public sealed record RegistrationProductionUris(
    [property: JsonPropertyName("redirectUris")]           string[]? RedirectUris,
    [property: JsonPropertyName("postLogoutRedirectUris")] string[]? PostLogoutRedirectUris
);

public sealed record RegistrationRbacInfo(
    [property: JsonPropertyName("applicationCode")] string ApplicationCode,
    [property: JsonPropertyName("applicationName")] string ApplicationName,
    [property: JsonPropertyName("description")]     string? Description,
    [property: JsonPropertyName("resourceTypes")]   RegistrationResourceType[]? ResourceTypes,
    [property: JsonPropertyName("roles")]           RegistrationRole[]? Roles,
    [property: JsonPropertyName("testUserRole")]    string? TestUserRole
);

public sealed record RegistrationResourceType(
    [property: JsonPropertyName("code")]              string Code,
    [property: JsonPropertyName("name")]              string Name,
    [property: JsonPropertyName("supportsInstances")] bool? SupportsInstances
);

public sealed record RegistrationRole(
    [property: JsonPropertyName("code")]        string Code,
    [property: JsonPropertyName("name")]        string Name,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("isSystem")]    bool? IsSystem
);

public sealed record RegistrationSettingsInfo(
    [property: JsonPropertyName("definitions")] RegistrationSettingDefinition[]? Definitions
);

public sealed record RegistrationSettingDefinition(
    [property: JsonPropertyName("key")]           string Key,
    [property: JsonPropertyName("displayName")]   string? DisplayName,
    [property: JsonPropertyName("description")]   string? Description,
    [property: JsonPropertyName("category")]      string? Category,
    [property: JsonPropertyName("dataType")]      string DataType,
    [property: JsonPropertyName("defaultValue")]  object? DefaultValue,
    [property: JsonPropertyName("isSecret")]      bool? IsSecret,
    [property: JsonPropertyName("allowedScopes")] string[]? AllowedScopes
);
