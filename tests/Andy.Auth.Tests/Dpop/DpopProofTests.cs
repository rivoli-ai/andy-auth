using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Andy.Auth.Dpop;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Andy.Auth.Tests.Dpop;

public sealed class DpopProofTests
{
    private static readonly Uri Target = new("https://api.example/resource?filter=1");
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupportedKey_ValidatesAndSendsOnlyPublicMaterial(bool rsa)
    {
        using var key = new Key(rsa);
        var proof = DpopProof.Create(key.Credentials, "GET", Target, "access");
        using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(proof.Split('.')[0]));
        var jwk = header.RootElement.GetProperty("jwk");
        Assert.False(jwk.TryGetProperty("d", out _));
        var result = await Validator().ValidateAsync(proof, "GET", Target, Lifetime, "access");
        Assert.True(result.Succeeded);
        Assert.Equal(Base64UrlEncoder.Encode(JsonWebKeyConverter.ConvertFromSecurityKey(key.Credentials.Key).ComputeJwkThumbprint()), result.Thumbprint);
    }

    [Theory]
    [InlineData("typ")]
    [InlineData("alg")]
    [InlineData("private")]
    [InlineData("remote")]
    [InlineData("crit")]
    [InlineData("htm")]
    [InlineData("htu")]
    [InlineData("query")]
    [InlineData("fragment")]
    [InlineData("http")]
    [InlineData("ath")]
    [InlineData("missing-ath")]
    [InlineData("old")]
    [InlineData("future")]
    [InlineData("jti")]
    [InlineData("duplicate-payload")]
    [InlineData("duplicate-header")]
    [InlineData("signature")]
    public async Task InvalidProof_RejectedBeforeReplayReservation(string defect)
    {
        using var key = new Key(false);
        var proof = DpopProof.Create(key.Credentials, "GET", Target, "access");
        var parts = proof.Split('.');
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64UrlEncoder.Decode(parts[0]))!;
        var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64UrlEncoder.Decode(parts[1]))!;
        void H(string name, object value) => header[name] = JsonSerializer.SerializeToElement(value);
        void P(string name, object value) => payload[name] = JsonSerializer.SerializeToElement(value);
        switch (defect)
        {
            case "typ": H("typ", "JWT"); break;
            case "alg": H("alg", "HS256"); break;
            case "private":
                var jwk = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(header["jwk"].GetRawText())!;
                jwk["d"] = JsonSerializer.SerializeToElement("private"); H("jwk", jwk); break;
            case "remote": H("jku", "https://attacker.example/key"); break;
            case "crit": H("crit", new[] { "extension" }); break;
            case "htm": P("htm", "POST"); break;
            case "htu": P("htu", "https://other.example/resource"); break;
            case "query": P("htu", Target.AbsoluteUri); break;
            case "fragment": P("htu", "https://api.example/resource#fragment"); break;
            case "http": P("htu", "http://api.example/resource"); break;
            case "ath": P("ath", "wrong"); break;
            case "missing-ath": payload.Remove("ath"); break;
            case "old": P("iat", DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds()); break;
            case "future": P("iat", DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeSeconds()); break;
            case "jti": P("jti", "\n"); break;
        }
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);
        if (defect == "duplicate-header") headerJson = headerJson[..^1] + ",\"typ\":\"dpop+jwt\"}";
        if (defect == "duplicate-payload") payloadJson = payloadJson[..^1] + ",\"htm\":\"GET\"}";
        // Re-sign modified claims so each failure exercises semantic validation.
        var signingInput = Base64UrlEncoder.Encode(headerJson) + "." + Base64UrlEncoder.Encode(payloadJson);
        var bytes = System.Text.Encoding.ASCII.GetBytes(signingInput);
        var signature = key.Ec!.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (defect == "signature") signature[0] ^= 1;
        proof = signingInput + "." + Base64UrlEncoder.Encode(signature);
        var store = new ReplayStore();
        Assert.False((await Validator(store).ValidateAsync(proof, "GET", Target, Lifetime, "access")).Succeeded);
        Assert.Equal(0, store.Attempts);
    }

    [Fact]
    public async Task NonceChallenge_DoesNotConsumeProof_AndReplaysAreRejected()
    {
        using var key = new Key(false);
        var validator = Validator();
        var proof = DpopProof.Create(key.Credentials, "POST", Target, nonce: "nonce");
        var challenge = await validator.ValidateAsync(proof, "POST", Target, Lifetime, nonceValidator: (_, _) => false);
        Assert.Equal("use_dpop_nonce", challenge.Error);
        Assert.NotNull(challenge.Thumbprint);
        Assert.True((await validator.ValidateAsync(proof, "POST", Target, Lifetime, nonceValidator: (nonce, _) => nonce == "nonce")).Succeeded);
        Assert.False((await validator.ValidateAsync(proof, "POST", Target, Lifetime)).Succeeded);
    }

    [Fact]
    public async Task ReplayStoreOutage_PropagatesForTransientDenial()
    {
        using var key = new Key(false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => new DpopProofValidator(new BrokenStore(), TimeProvider.System)
            .ValidateAsync(DpopProof.Create(key.Credentials, "GET", Target), "GET", Target, Lifetime));
    }

    private static DpopProofValidator Validator(ReplayStore? store = null) => new(store ?? new(), TimeProvider.System);
    private sealed class ReplayStore : IDpopReplayStore
    {
        private readonly ConcurrentDictionary<string, bool> used = new();
        public int Attempts;
        public Task<bool> TryUseAsync(string thumbprint, string id, TimeSpan retention, CancellationToken cancellationToken)
        { Interlocked.Increment(ref Attempts); return Task.FromResult(used.TryAdd(thumbprint + id, true)); }
    }
    private sealed class BrokenStore : IDpopReplayStore
    {
        public Task<bool> TryUseAsync(string thumbprint, string id, TimeSpan retention, CancellationToken cancellationToken) => throw new InvalidOperationException("unavailable");
    }
    private sealed class Key : IDisposable
    {
        public ECDsa? Ec { get; }
        private RSA? Rsa { get; }
        public SigningCredentials Credentials { get; }
        public Key(bool rsa)
        {
            if (rsa) { Rsa = RSA.Create(2048); Credentials = new(new RsaSecurityKey(Rsa), SecurityAlgorithms.RsaSha256); }
            else { Ec = ECDsa.Create(ECCurve.NamedCurves.nistP256); Credentials = new(new ECDsaSecurityKey(Ec), SecurityAlgorithms.EcdsaSha256); }
        }
        public void Dispose() { Ec?.Dispose(); Rsa?.Dispose(); }
    }
}
