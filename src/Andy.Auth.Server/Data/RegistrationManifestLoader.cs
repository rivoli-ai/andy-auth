// Copyright (c) Rivoli AI 2026. All rights reserved.
using System.Text.Json;

namespace Andy.Auth.Server.Data;

/// <summary>
/// Discovers and parses registration manifests on startup.
///
/// Discovery order (first match per service wins):
/// 1. Paths listed in the <c>Registrations:ManifestPaths</c> configuration array.
/// 2. Paths listed in the <c>REGISTRATIONS__MANIFEST_PATHS</c> environment variable
///    (separator: ';' on Windows, ':' elsewhere — follows PATH conventions).
/// 3. The default fallback <c>/etc/andy/registrations</c> inside containers.
///
/// Each path may be a specific JSON file (<c>/path/andy-policies.json</c>) or a
/// directory (<c>/etc/andy/registrations/</c>). Directories are shallow-scanned
/// for <c>*.json</c>; files that fail to parse are logged and skipped, not fatal.
/// </summary>
public sealed class RegistrationManifestLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private readonly IConfiguration _configuration;
    private readonly ILogger<RegistrationManifestLoader> _logger;

    public RegistrationManifestLoader(IConfiguration configuration, ILogger<RegistrationManifestLoader> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public IReadOnlyList<RegistrationManifest> LoadAll()
    {
        var paths = ResolveSearchPaths();
        var manifests = new Dictionary<string, RegistrationManifest>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        {
            foreach (var file in EnumerateManifestFiles(path))
            {
                if (TryLoad(file, out var manifest) && manifest is not null)
                {
                    if (manifests.ContainsKey(manifest.Service.Name))
                    {
                        _logger.LogDebug("Skipping {File} — manifest for {Service} already loaded from earlier path.",
                            file, manifest.Service.Name);
                        continue;
                    }
                    manifests[manifest.Service.Name] = manifest;
                    _logger.LogInformation("Loaded registration manifest for {Service} from {File}.",
                        manifest.Service.Name, file);
                }
            }
        }

        _logger.LogInformation("Registration manifest load complete: {Count} manifest(s).", manifests.Count);
        return manifests.Values.ToList();
    }

    private IReadOnlyList<string> ResolveSearchPaths()
    {
        var paths = new List<string>();

        var configured = _configuration.GetSection("Registrations:ManifestPaths").Get<string[]>();
        if (configured is not null && configured.Length > 0)
        {
            paths.AddRange(configured);
        }

        var envVar = Environment.GetEnvironmentVariable("REGISTRATIONS__MANIFEST_PATHS");
        if (!string.IsNullOrWhiteSpace(envVar))
        {
            var separator = OperatingSystem.IsWindows() ? ';' : ':';
            paths.AddRange(envVar.Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        if (paths.Count == 0)
        {
            const string defaultPath = "/etc/andy/registrations";
            if (Directory.Exists(defaultPath))
            {
                paths.Add(defaultPath);
            }
        }

        return paths;
    }

    private IEnumerable<string> EnumerateManifestFiles(string path)
    {
        if (File.Exists(path))
        {
            yield return path;
            yield break;
        }

        if (!Directory.Exists(path))
        {
            _logger.LogDebug("Registration manifest path {Path} does not exist; skipping.", path);
            yield break;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*.json", SearchOption.TopDirectoryOnly))
        {
            yield return file;
        }
    }

    private bool TryLoad(string file, out RegistrationManifest? manifest)
    {
        manifest = null;
        try
        {
            using var stream = File.OpenRead(file);
            manifest = JsonSerializer.Deserialize<RegistrationManifest>(stream, JsonOptions);
            if (manifest is null || manifest.Service is null || string.IsNullOrWhiteSpace(manifest.Service.Name))
            {
                _logger.LogWarning("Manifest {File} missing required 'service.name'; skipping.", file);
                return false;
            }
            return true;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Manifest {File} failed to parse; skipping.", file);
            return false;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Manifest {File} could not be read; skipping.", file);
            return false;
        }
    }
}
