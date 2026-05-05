# `PersistedDevelopmentKeys`: negative-path tests + clearer corruption errors

## Problem

`PersistedDevelopmentKeys.LoadOrCreate` only has happy-path test coverage:
- generates the key on first call
- returns the same key on second call
- doesn't overwrite an existing file
- produces a 2048-bit RSA usable for SignData/VerifyData
- sets 0600 perms on Unix

Three failure modes the post-merge review flagged are untested:

1. **Malformed PEM** — `signing.key` exists but contents are corrupt (manual edit, fs corruption, ransomware). `RSA.ImportFromPem` throws `CryptographicException` with no context about *which* file failed; the exception bubbles up through the OpenIddict server boot and the operator sees a stack trace deep in the framework.

2. **Half-write recovery** — first boot is interrupted between `WriteAllText("signing.key", …)` and `WriteAllText("encryption.key", …)`. On second boot, `signing.key` exists and loads fine; `encryption.key` is missing → regenerated. Asymmetric. Or: the file exists but is empty/truncated. Same trap as #1.

3. **Unwritable directory** — `OpenIddict:SigningKeys:Path` points at a read-only mount or a directory the service account doesn't have write perms on. `Directory.CreateDirectory` succeeds (it's idempotent for existing dirs), `File.WriteAllText` then throws `UnauthorizedAccessException` / `IOException`.

Silently regenerating on corruption is the wrong fix — that'd invalidate every cached JWT held by every consumer service. Hard-fail with a helpful message is the right answer; the test suite needs to pin that contract so a future "let's just regenerate" change can't slip in.

## Fix

### Tests

Add to `tests/Andy.Auth.Server.Tests/Configuration/PersistedDevelopmentKeysTests.cs`:

- `LoadOrCreate_MalformedPem_ThrowsWithFilePathInMessage`
- `LoadOrCreate_EmptyFile_ThrowsWithFilePathInMessage`
- `LoadOrCreate_TruncatedPem_ThrowsWithFilePathInMessage`
- `LoadOrCreate_UnwritableDirectory_PropagatesIoException` (Unix only — Windows ACLs are different)

### Helper hardening

Wrap the `RSA.ImportFromPem` call in `LoadOrCreate` with a try/catch that rethrows as a more helpful exception mentioning the file path. Don't silently regenerate.

```csharp
try
{
    rsa.ImportFromPem(File.ReadAllText(filePath));
    return rsa;
}
catch (CryptographicException inner)
{
    rsa.Dispose();
    throw new InvalidOperationException(
        $"Persisted signing/encryption key at '{filePath}' is corrupt or " +
        $"not a valid PKCS#8 PEM keypair. Refusing to regenerate — that " +
        $"would invalidate every issued JWT. Restore the file from backup " +
        $"or delete it intentionally to trigger a fresh keypair.",
        inner);
}
```

## Acceptance criteria

- [ ] Four new tests cover the three failure modes (malformed PEM, empty file, truncated PEM, unwritable dir).
- [ ] `LoadOrCreate` wraps corruption errors with a message that includes the file path and explicitly states it will not auto-regenerate.
- [ ] No existing test changes shape.
- [ ] Build clean, full server suite green-or-same as `main`.

## Files touched

- `src/Andy.Auth.Server/Configuration/PersistedDevelopmentKeys.cs` — try/catch wrapper around `ImportFromPem`.
- `tests/Andy.Auth.Server.Tests/Configuration/PersistedDevelopmentKeysTests.cs` — four new tests.

## Notes

- "Recovery" in the original review note means "graceful failure with a clear pointer to a fix", not "silent regenerate".
- Symlink-pivot defence (`Path.GetFullPath` realpath check) is a separate hardening item — out of scope for this PR.
