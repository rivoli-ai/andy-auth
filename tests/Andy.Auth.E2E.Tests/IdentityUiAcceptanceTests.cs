using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Playwright;

namespace Andy.Auth.E2E.Tests;

public sealed class IdentityUiAcceptanceTests : E2ETestBase
{
    [Theory]
    [InlineData(1440)]
    [InlineData(375)]
    public async Task SignInStatesKeyboardAndReturnUrl(int width)
    {
        var before = Environment.GetEnvironmentVariable("ANDY_UI_EVIDENCE_PHASE") == "before";
        await Page.SetViewportSizeAsync(width, 900);
        await NavigateToAsync("/Account/Login?returnUrl=%2FSession");
        await Capture(width, "empty");
        if (!before)
        {
            Assert.Equal("username", await Page.GetAttributeAsync("input[name=Email]", "autocomplete"));
            Assert.Equal("current-password", await Page.GetAttributeAsync("input[name=Password]", "autocomplete"));
            Assert.True(await Page.EvaluateAsync<bool>("document.documentElement.scrollWidth <= innerWidth + 1"));
            await Page.FocusAsync("input[name=Email]");
            await Page.Keyboard.PressAsync("Tab");
            Assert.Equal("Password", await Page.EvaluateAsync<string>("document.activeElement.name"));
            await Assertions.Expect(Page.Locator("input[name=Password]")).ToHaveCSSAsync("outline-width", "2px");
        }
        await Page.FillAsync("input[name=Email]", "user@test.com");
        await Page.FillAsync("input[name=Password]", "User123!");
        await Capture(width, "populated");
        await Page.FillAsync("input[name=Password]", "Incorrect123!");
        await Page.ClickAsync("button[type=submit]");
        await Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
        Assert.Contains("Invalid login attempt", await Page.ContentAsync());
        await Capture(width, "failed");
        await Page.FillAsync("input[name=Password]", "User123!");
        // Hold the actual submit event immediately before navigation so the
        // browser can capture its pending UI; then release the native POST.
        await Page.EvaluateAsync("document.querySelector('form').addEventListener('submit', event => event.preventDefault(), {once:true})");
        await Page.ClickAsync("button[type=submit]");
        await Capture(width, "loading");
        if (!before)
        {
            Assert.True(await Page.IsDisabledAsync("button[type=submit]"));
            Assert.Contains("Signing in", await Page.InnerTextAsync("button[type=submit]"));
        }
        await Page.EvaluateAsync("HTMLFormElement.prototype.submit.call(document.querySelector('form'))");
        await Page.WaitForURLAsync("**/Session");
        await Capture(width, "sessions");
        await Context.ClearCookiesAsync();
        await LoginAsAdminAsync();
        await NavigateToAsync("/Admin");
        await Capture(width, "admin");
        if (!before && width == 1440)
        {
            await Context.ClearCookiesAsync();
            await NavigateToAsync("/Account/Login");
            await Page.EvaluateAsync("document.documentElement.style.zoom = '2'");
            Assert.True(await Page.EvaluateAsync<bool>("document.documentElement.scrollWidth <= innerWidth + 1"));
            await Capture(width, "zoom-200");
        }
    }

    [Fact]
    public async Task AuthenticatorAndRecoveryReturnToOriginalApplication()
    {
        await Page.SetViewportSizeAsync(375, 900);
        await LoginAsUserAsync();
        await NavigateToAsync("/TwoFactor/EnableAuthenticator");
        var key = (await Page.InnerTextAsync(".manual-key")).Replace(" ", "").Trim();
        await Page.FillAsync("input[name=Code]", Totp(key));
        await Page.ClickAsync("form[action='/TwoFactor/EnableAuthenticator'] button[type=submit]");
        var recovery = await Page.Locator(".code-item").First.InnerTextAsync();
        await Page.GetByRole(AriaRole.Button, new() { Name = "Open navigation" }).ClickAsync();
        await LogoutAsync();
        foreach (var useRecovery in new[] { false, true })
        {
            await NavigateToAsync("/Account/Login?returnUrl=%2FSession");
            await Page.FillAsync("input[name=Email]", "user@test.com");
            await Page.FillAsync("input[name=Password]", "User123!");
            await Page.ClickAsync("button[type=submit]");
            await Page.WaitForURLAsync("**/Account/LoginWith2fa**");
            var recoveryLink = Page.Locator("a[href*='LoginWithRecoveryCode']");
            Assert.Contains("returnUrl=%2FSession", await recoveryLink.GetAttributeAsync("href"));
            if (useRecovery)
            {
                await recoveryLink.ClickAsync();
                await Capture(375, "recovery");
                await Page.FillAsync("input[name=RecoveryCode]", recovery);
            }
            else
            {
                await Capture(375, "mfa");
                await Page.FillAsync("input[name=TwoFactorCode]", Totp(key));
            }
            await Page.ClickAsync("form[action*='LoginWith'] button[type=submit]");
            await Page.WaitForURLAsync("**/Session");
            await Page.GetByRole(AriaRole.Button, new() { Name = "Open navigation" }).ClickAsync();
            await LogoutAsync();
        }
    }

    private static string Totp(string key)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        var buffer = 0; var bits = 0;
        foreach (var character in key.ToUpperInvariant())
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character); bits += 5;
            if (bits >= 8) { bits -= 8; bytes.Add((byte)(buffer >> bits)); }
        }
        var counter = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        if (BitConverter.IsLittleEndian) Array.Reverse(counter);
        var hash = HMACSHA1.HashData(bytes.ToArray(), counter);
        var offset = hash[^1] & 15;
        var number = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (number % 1000000).ToString("D6");
    }

    private async Task Capture(int width, string state)
    {
        var directory = Environment.GetEnvironmentVariable("ANDY_UI_EVIDENCE_DIR");
        if (string.IsNullOrWhiteSpace(directory)) return;
        Directory.CreateDirectory(directory);
        var phase = Environment.GetEnvironmentVariable("ANDY_UI_EVIDENCE_PHASE") ?? "after";
        if (phase == "before" && state is "sessions" or "admin") return;
        var path = Path.Combine(directory, $"{phase}-{width}-{state}.png");
        await Page.ScreenshotAsync(new() { Path = path, FullPage = true });
        var metrics = await Page.EvaluateAsync<JsonElement>("""
            () => {
                const button = document.querySelector('button[type=submit]');
                const email = document.querySelector('input[name=Email]');
                const style = button && getComputedStyle(button);
                const inputStyle = email && getComputedStyle(email);
                const error = document.querySelector('.validation-summary-errors li');
                return { viewport: innerWidth, scrollWidth: document.documentElement.scrollWidth,
                    buttonText: button?.textContent.trim(), buttonDisabled: button?.disabled,
                    buttonColor: style?.color, buttonBackground: style?.backgroundColor,
                    inputBorder: inputStyle?.borderTopColor, inputBackground: inputStyle?.backgroundColor,
                    placeholderColor: email && getComputedStyle(email, '::placeholder').color,
                    focusColor: inputStyle?.outlineColor,
                    errorColor: error && getComputedStyle(error).color,
                    errorBackground: error && getComputedStyle(error.closest('.validation-summary-errors')).backgroundColor,
                    emailAutocomplete: email?.autocomplete, focus: document.activeElement?.getAttribute('name') };
            }
            """);
        await File.WriteAllTextAsync(Path.Combine(directory, $"{phase}-{width}-{state}.json"), metrics.ToString());
    }
}
