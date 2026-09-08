# Identity UI acceptance — 2026-09-08

The existing shared Razor theme from PR #183 is retained. This follow-up fixes MFA enrollment and adds sign-in submission feedback, duplicate-submit prevention, keyboard focus outlines, and higher-contrast input borders, placeholders and validation text. It uses native Razor controls and CSS; no Astryx React components are installed.

## Browser evidence

Chromium, 1440×900 and 375×900. “Before” uses the exact login template from commit `2bada8b`, rendered against the same isolated in-memory test backend as the current template. Only the sign-in template is a historical comparison; authenticated and MFA screenshots show the current implementation. These are synthetic test accounts, and authenticator keys/recovery codes are not captured.

The loading capture holds the form submit event immediately before navigation, records the actual submit-handler state, then releases the native POST. This provides a deterministic pending-state comparison without inventing a visual or waiting on an external service. The same test verifies the completed login returns to `/Session`.

| State | Desktop before | Desktop after | 375px before | 375px after |
|---|---|---|---|---|
| Empty | [View](evidence/before-1440-empty.png) | [View](evidence/after-1440-empty.png) | [View](evidence/before-375-empty.png) | [View](evidence/after-375-empty.png) |
| Populated | [View](evidence/before-1440-populated.png) | [View](evidence/after-1440-populated.png) | [View](evidence/before-375-populated.png) | [View](evidence/after-375-populated.png) |
| Failed | [View](evidence/before-1440-failed.png) | [View](evidence/after-1440-failed.png) | [View](evidence/before-375-failed.png) | [View](evidence/after-375-failed.png) |
| Loading | [View](evidence/before-1440-loading.png) | [View](evidence/after-1440-loading.png) | [View](evidence/before-375-loading.png) | [View](evidence/after-375-loading.png) |

Additional current captures: [desktop administration](evidence/after-1440-admin.png), [mobile administration](evidence/after-375-admin.png), [desktop sessions](evidence/after-1440-sessions.png), [mobile sessions](evidence/after-375-sessions.png), [MFA](evidence/after-375-mfa.png), [recovery login](evidence/after-375-recovery.png), and [200% CSS zoom](evidence/after-1440-zoom-200.png). JSON files alongside the screenshots record viewport and computed style values.

## Verified behavior

- Correct username/current-password autocomplete attributes and associated labels; native fields retain password-manager-compatible semantics.
- Keyboard Tab moves from email to password and exposes a visible 2px outline. No horizontal overflow at 1440px or 375px, or under the desktop 200% CSS-zoom check.
- Invalid credentials show validation; pending submission disables repeat submissions and announces its state through the button label and form busy attribute.
- Valid login preserves the original return URL. The browser reaches authenticated Sessions and Administration pages; the mobile navigation supports sign-out.
- Authenticator enrollment now succeeds: display-only shared-key/QR fields are excluded from POST binding/validation, while the submitted code is required and verified.
- Real authenticator and recovery-code sign-in each return to the original `/Session` destination. The recovery link preserves the return URL.

## Contrast measurements

Measured from Chromium computed colors in `after-1440-failed.json`, compositing the translucent error background over white:

| Element | Ratio |
|---|---:|
| Sign-in button text | 19.80:1 |
| Placeholder text | 4.74:1 |
| Input boundary | 4.54:1 |
| Keyboard outline | 5.05:1 |
| Validation text | 5.70:1 |

These exceed the relevant [4.5:1 normal-text threshold](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) and [3:1 non-text threshold](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html). This is a focused check, not a claim of complete WCAG conformance.

## Reproduce

```sh
ANDY_UI_EVIDENCE_PHASE=after ANDY_UI_EVIDENCE_DIR=/absolute/path/to/evidence \
  dotnet test tests/Andy.Auth.E2E.Tests --filter FullyQualifiedName~IdentityUiAcceptanceTests
ANDY_TEST_REDIS=localhost:16379 dotnet test andy-auth.sln
```

The first command covers all three new browser cases (two viewport cases and one MFA/recovery case). For the historical comparison, temporarily replace only `Views/Account/Login.cshtml` with its `2bada8b` version in an isolated worktree, set phase `before`, and filter to `SignInStatesKeyboardAndReturnUrl`; restore the current template afterwards.

## Remaining manual acceptance

A real password-manager save/fill interaction, native browser zoom, and assistive-technology review have not been performed. Synthetic field filling and CSS zoom do not substitute for those checks. Keep #181 open until the requested manual acceptance is recorded.
