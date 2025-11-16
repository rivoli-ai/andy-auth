# Passkeys (WebAuthn) Support in Andy Auth

Andy Auth Server can support **Passkeys** (WebAuthn/FIDO2) for passwordless authentication.

## What are Passkeys?

Passkeys are a modern, phishing-resistant authentication method supported by:
- Apple (iCloud Keychain, Touch ID, Face ID)
- Google (Password Manager, Android biometrics)
- Microsoft (Windows Hello)
- 1Password, Bitwarden, etc.

**Benefits:**
- ✅ No passwords to remember
- ✅ Phishing-resistant (cryptographic)
- ✅ Fast (biometric authentication)
- ✅ Cross-device sync
- ✅ Better UX

## Architecture with Passkeys

```
┌─────────────────────────────────────────────┐
│          User Authentication Flow            │
└─────────────────────────────────────────────┘

Option 1: Passkey (Passwordless)
  User → Click "Sign in with passkey"
      → Browser prompts for biometric/PIN
      → WebAuthn ceremony
      → Andy.Auth.Server validates
      → Issues OAuth token

Option 2: Password (Traditional)
  User → Enter email/password
      → Andy.Auth.Server validates
      → Issues OAuth token

Option 3: Social Login (Federated)
  User → Click "Sign in with Google"
      → Redirects to Google
      → Returns to Andy.Auth.Server
      → Issues OAuth token
```

## Implementation Options

### Option A: Use FIDO2 Library (Recommended)

**NuGet Package:**
```bash
cd src/Andy.Auth.Server
dotnet add package Fido2.NetFramework
dotnet add package Fido2.Models
```

**Features:**
- Full WebAuthn support
- Attestation and assertion
- Credential storage
- Metadata service
- Compliant with W3C spec

### Option B: Use Identity.WebAuthn

**NuGet Package:**
```bash
dotnet add package Microsoft.AspNetCore.Authentication.WebAuthn
```

**Features:**
- Microsoft official package
- Integrates with ASP.NET Core Identity
- Simpler API
- Less configuration

## Database Schema for Passkeys

**Add to IdentityDbContext:**

```csharp
public class PasskeyCredential
{
    public Guid Id { get; set; }
    public required string UserId { get; set; }
    public required byte[] CredentialId { get; set; }
    public required byte[] PublicKey { get; set; }
    public required byte[] UserHandle { get; set; }
    public uint SignatureCounter { get; set; }
    public string? CredentialType { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? DeviceName { get; set; } // "iPhone 15 Pro", "MacBook Pro"
    public bool IsBackedUp { get; set; } // iCloud Keychain sync

    // Navigation
    public ApplicationUser User { get; set; } = null!;
}
```

## Registration Flow

**User Registration with Passkey:**

```csharp
[HttpPost("register/passkey/begin")]
public async Task<IActionResult> BeginPasskeyRegistration([FromBody] string username)
{
    // Create new user
    var user = new ApplicationUser { UserName = username };
    await _userManager.CreateAsync(user);

    // Generate challenge
    var fidoUser = new Fido2User
    {
        DisplayName = username,
        Name = username,
        Id = Encoding.UTF8.GetBytes(user.Id)
    };

    var authenticatorSelection = new AuthenticatorSelection
    {
        RequireResidentKey = true,
        UserVerification = UserVerificationRequirement.Required
    };

    var options = _fido2.RequestNewCredential(
        fidoUser,
        excludeCredentials: new List<PublicKeyCredentialDescriptor>(),
        authenticatorSelection,
        AttestationConvictionRequirement.None
    );

    // Store challenge in session/cache
    HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

    return Json(options);
}

[HttpPost("register/passkey/complete")]
public async Task<IActionResult> CompletePasskeyRegistration(
    [FromBody] AuthenticatorAttestationRawResponse attestationResponse)
{
    // Retrieve challenge
    var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
    var options = CredentialCreateOptions.FromJson(jsonOptions);

    // Verify attestation
    var success = await _fido2.MakeNewCredentialAsync(
        attestationResponse,
        options,
        async (args, cancellationToken) => true
    );

    // Store credential
    var credential = new PasskeyCredential
    {
        UserId = user.Id,
        CredentialId = success.Result.CredentialId,
        PublicKey = success.Result.PublicKey,
        UserHandle = success.Result.User.Id,
        SignatureCounter = success.Result.Counter,
        DeviceName = "User's device", // From user agent
        CreatedAt = DateTime.UtcNow
    };

    await _context.PasskeyCredentials.AddAsync(credential);
    await _context.SaveChangesAsync();

    return Ok(new { success = true });
}
```

## Authentication Flow

**Login with Passkey:**

```csharp
[HttpPost("login/passkey/begin")]
public async Task<IActionResult> BeginPasskeyLogin()
{
    // Get all credentials (for this domain)
    var allowedCredentials = await _context.PasskeyCredentials
        .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
        .ToListAsync();

    var options = _fido2.GetAssertionOptions(
        allowedCredentials,
        UserVerificationRequirement.Required
    );

    HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

    return Json(options);
}

[HttpPost("login/passkey/complete")]
public async Task<IActionResult> CompletePasskeyLogin(
    [FromBody] AuthenticatorAssertionRawResponse assertionResponse)
{
    // Retrieve challenge
    var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
    var options = AssertionOptions.FromJson(jsonOptions);

    // Find credential
    var credential = await _context.PasskeyCredentials
        .Include(c => c.User)
        .FirstOrDefaultAsync(c => c.CredentialId == assertionResponse.Id);

    if (credential == null)
        return Unauthorized();

    // Verify assertion
    var success = await _fido2.MakeAssertionAsync(
        assertionResponse,
        options,
        credential.PublicKey,
        credential.SignatureCounter,
        async (args, cancellationToken) => true
    );

    // Update counter and last used
    credential.SignatureCounter = success.Counter;
    credential.LastUsedAt = DateTime.UtcNow;
    await _context.SaveChangesAsync();

    // Sign in user
    await _signInManager.SignInAsync(credential.User, isPersistent: true);

    return Ok(new { success = true, userId = credential.UserId });
}
```

## Frontend Integration

**HTML/JavaScript (Angular example):**

```typescript
// Register passkey
async registerPasskey(username: string) {
  // 1. Get challenge from server
  const beginResponse = await fetch('/register/passkey/begin', {
    method: 'POST',
    body: JSON.stringify(username)
  });
  const options = await beginResponse.json();

  // 2. Create credential with WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: options
  });

  // 3. Send to server
  await fetch('/register/passkey/complete', {
    method: 'POST',
    body: JSON.stringify(credential)
  });
}

// Login with passkey
async loginWithPasskey() {
  // 1. Get challenge
  const beginResponse = await fetch('/login/passkey/begin', {
    method: 'POST'
  });
  const options = await beginResponse.json();

  // 2. Get credential
  const assertion = await navigator.credentials.get({
    publicKey: options
  });

  // 3. Verify
  const result = await fetch('/login/passkey/complete', {
    method: 'POST',
    body: JSON.stringify(assertion)
  });

  // User is now authenticated!
}
```

## Configuration

**appsettings.json:**

```json
{
  "Fido2": {
    "ServerDomain": "auth.rivoli.ai",
    "ServerName": "Andy Auth",
    "Origins": [
      "https://auth.rivoli.ai",
      "https://wagram.ai"
    ],
    "TimestampDriftTolerance": 300000
  }
}
```

**Program.cs:**

```csharp
// Add FIDO2
builder.Services.AddFido2(options =>
{
    options.ServerDomain = builder.Configuration["Fido2:ServerDomain"];
    options.ServerName = builder.Configuration["Fido2:ServerName"];
    options.Origins = builder.Configuration.GetSection("Fido2:Origins").Get<HashSet<string>>();
    options.TimestampDriftTolerance = builder.Configuration.GetValue<int>("Fido2:TimestampDriftTolerance");
});
```

## Migration: 20250115_AddPasskeys.cs

```csharp
public partial class AddPasskeys : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "PasskeyCredentials",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                UserId = table.Column<string>(nullable: false),
                CredentialId = table.Column<byte[]>(nullable: false),
                PublicKey = table.Column<byte[]>(nullable: false),
                UserHandle = table.Column<byte[]>(nullable: false),
                SignatureCounter = table.Column<long>(nullable: false),
                CredentialType = table.Column<string>(maxLength: 50, nullable: true),
                CreatedAt = table.Column<DateTime>(nullable: false),
                LastUsedAt = table.Column<DateTime>(nullable: true),
                DeviceName = table.Column<string>(maxLength: 200, nullable: true),
                IsBackedUp = table.Column<bool>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_PasskeyCredentials", x => x.Id);
                table.ForeignKey(
                    name: "FK_PasskeyCredentials_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "AspNetUsers",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_PasskeyCredentials_UserId",
            table: "PasskeyCredentials",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_PasskeyCredentials_CredentialId",
            table: "PasskeyCredentials",
            column: "CredentialId",
            unique: true);
    }
}
```

## User Experience

**Registration:**
1. User enters email
2. Clicks "Create account with passkey"
3. Browser prompts: "Use Touch ID / Face ID / Windows Hello?"
4. User authenticates biometrically
5. Account created instantly (no password needed!)

**Login:**
1. User navigates to login page
2. Clicks "Sign in with passkey"
3. Browser shows available passkeys
4. User selects their account
5. Authenticates with biometric
6. Logged in!

**Cross-device:**
- Create passkey on iPhone → syncs to Mac via iCloud Keychain
- Create on Android → syncs to Chrome on desktop via Google Password Manager

## Benefits for Andy Auth

**Security:**
- ✅ Phishing-resistant (public key cryptography)
- ✅ No password database to breach
- ✅ Replay attack protection
- ✅ Attestation for device verification

**UX:**
- ✅ Faster login (2 clicks vs typing password)
- ✅ No "forgot password" flow
- ✅ Works offline (credential stored locally)
- ✅ Cross-platform

**Compliance:**
- ✅ FIDO2 certified
- ✅ W3C standard
- ✅ Meets modern security requirements

## Implementation Timeline

**Phase 1: Basic Passkey Support (Week 1)**
- Add Fido2.NetFramework package
- Implement registration/login endpoints
- Add database schema
- Test with Chrome/Safari

**Phase 2: Frontend Integration (Week 2)**
- Add passkey UI to login page
- Implement registration flow
- Add credential management page
- Test cross-browser

**Phase 3: Advanced Features (Week 3)**
- Multi-credential support (multiple devices)
- Credential naming/management
- Backup methods (if passkey lost)
- Device attestation

**Phase 4: Production (Week 4)**
- Security audit
- UX testing
- Documentation
- Gradual rollout

## Fallback Strategy

**Hybrid Authentication:**
- Primary: Passkeys (recommended)
- Fallback: Password (for older browsers)
- Alternative: Social login (Google, GitHub)

```
┌─────────────────────────────┐
│      Login Page             │
├─────────────────────────────┤
│  [Sign in with passkey]     │  ← Primary (best UX)
│                             │
│  ─────── or ────────        │
│                             │
│  Email: ______________      │
│  Password: ___________      │
│  [Sign in]                  │  ← Fallback
│                             │
│  [Sign in with Google]      │  ← Alternative
│  [Sign in with GitHub]      │
└─────────────────────────────┘
```

## Testing Passkeys Locally

**Requirements:**
- HTTPS (required for WebAuthn)
- Modern browser (Chrome 108+, Safari 16+, Edge 108+)
- Biometric device or security key

**Setup HTTPS locally:**
```bash
# Generate self-signed cert
dotnet dev-certs https --trust

# Or use mkcert
brew install mkcert
mkcert -install
mkcert localhost
```

**Test devices:**
- macOS: Touch ID, USB security key
- Windows: Windows Hello, USB security key
- iOS: Face ID / Touch ID
- Android: Fingerprint / Face unlock

## Resources

- [WebAuthn Guide](https://webauthn.guide/)
- [Fido2.NetFramework Docs](https://github.com/passwordless-lib/fido2-net-lib)
- [Passkeys.dev](https://passkeys.dev/)
- [Apple Passkeys](https://developer.apple.com/passkeys/)
- [Google Passkeys](https://developers.google.com/identity/passkeys)

## Cost

**Implementation:**
- Fido2.NetFramework: Free (open source)
- No additional infrastructure cost
- No third-party service fees

**Comparison:**
- Auth0 passkeys: $35/month+
- Clerk passkeys: Custom pricing
- Andy Auth passkeys: **$0** (included)

---

Would you like me to implement passkey support in Andy.Auth.Server as part of the initial setup?
