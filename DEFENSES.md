# Defenses

This demo shows what a malicious or over-privileged extension can do once it
runs in your browser — most sharply, the `cookies` panel and its
**pass-the-cookie** technique (see [PERMISSIONS.md](PERMISSIONS.md) and
[SECURITY.md](SECURITY.md)). This document is the other half: what actually
stops it.

There is no single control that neutralizes the attack. It has two distinct
phases — a hostile extension **gets installed**, then it **harvests and
replays** a session cookie — so you defend at both. The layers that carry the
most weight are **session binding** (makes a stolen cookie worthless) and
**extension control** (stops the harvest from ever happening).

A point worth keeping in front of every item below: once code with the
`cookies` permission runs in the browser, it operates on the *legitimate*
origin with a *legitimate*, already-authenticated session. Everything that
happens at login — passwords, MFA, FIDO2 keys, passkeys — is already behind
it. Only defenses that act on the **session after login** engage this attack
at all.

## 1. Kill the replay — session / token binding

The only class of defense that makes a stolen cookie *worthless* rather than
merely harder to obtain. It doesn't care how the cookie was stolen —
extension, adversary-in-the-middle proxy, infostealer, memory dump — so it
engages all of them at once.

- **DBSC (Device Bound Session Credentials)** — Chrome's direct answer to
  this attack. The session cookie is cryptographically bound to a private key
  held in the device TPM; the browser periodically proves possession. A cookie
  copied to another machine has no matching key, so the replayed session
  fails. Rolling out now, with Google and Microsoft as early adopters.
- **DPoP / mutual-TLS-bound tokens** — the OAuth / API-layer equivalent:
  the access token is bound to a key the client must prove it holds on every
  call.

If you deploy binding, every layer below becomes defense-in-depth rather than
load-bearing.

## 2. Stop the harvest — extension control

The attack requires an extension with `cookies` plus broad host access to
exist in the browser at all. On a managed fleet you can prevent that
outright.

- **Default-deny allowlisting** — `ExtensionInstallBlocklist: ["*"]` paired
  with an `ExtensionInstallAllowlist` of vetted extension IDs. The single
  highest-leverage preventive control for an organization.
- **Per-origin restriction** — `ExtensionSettings` / `runtime_blocked_hosts`
  to bar extensions from touching sensitive origins (your IdP,
  `login.microsoftonline.com`, banking, etc.) even when they are installed.
- **Block sideloading** — disable Developer Mode / `ExtensionUnpackedDisallowed`
  to close the "load unpacked" path this demo itself uses.
- **Vet permissions at review time.** The red flags are `cookies` + `<all_urls>`,
  `debugger`, `scripting`, `webRequest`, and `nativeMessaging`. Remember the
  demo's own lesson: a `scripting`-based network capture leaves **no**
  on-screen indicator, while the `debugger` route trips Chrome's unhidable
  banner — the permission tier is a starting point, not the whole risk
  picture.

### Acium extension control

[Acium](https://acium.io)'s extension control lets you **prevent specific
permissions globally** — set a policy once and any extension requesting a
disallowed permission (for example `cookies`, `debugger`, or `<all_urls>`
host access) is blocked across the whole fleet, regardless of who published
it or how it reaches the browser. Rather than allowlisting extensions one ID
at a time and re-reviewing on every update, you draw the line at the
capability itself: the permissions that make pass-the-cookie and silent
traffic capture possible simply never get granted. This turns the "vet
permissions at review time" step above from a manual, per-extension chore
into an enforced, catalog-wide guarantee.

## 3. Shrink the blast radius — session hygiene

Reduces what a stolen cookie is worth even without full binding.

- **Short session lifetimes** and aggressive idle timeouts.
- **Step-up re-authentication** on sensitive actions. Passkeys make this
  cheap — a Touch ID / Windows Hello tap instead of a full re-login — so it
  is far more palatable to demand often.
- **Cookie flags** — `__Host-` / `__Secure-` prefixes, `HttpOnly`, `Secure`,
  `SameSite`. Worth setting, but be honest about the limit: `HttpOnly` stops
  page JavaScript (XSS) and network proxies from reading a cookie — it does
  **not** stop the `chrome.cookies` API, which is exactly the capability this
  demo exercises.

## 4. Detect the replay — conditional / continuous access

Catches the cookie being *used* somewhere it shouldn't be.

- **Continuous evaluation** — Microsoft Entra Conditional Access + CAE,
  Google Context-Aware Access, or any CAEP-style engine that re-checks IP,
  geovelocity, and device posture *mid-session* rather than only at login. A
  cookie replayed from a new device or ASN triggers re-auth or revocation.
- **Impossible-travel and concurrent-session anomaly detection** in the IdP.
- **Device compliance gates** — the session is valid only from an enrolled,
  managed device.

## 5. Detect the extension itself

- **EDR / browser telemetry** flagging newly installed high-risk extensions.
- **Chrome Enterprise reporting** / browser management console inventorying
  every installed extension and its permissions across the fleet.

## Bottom line

- **For an organization:** session/token binding (§1) + extension control
  (§2, including Acium's global permission policy) + continuous access (§4)
  is a genuinely strong combination — it removes the cookie's value, the
  extension's ability to run or to hold the dangerous permission at all, and
  the ability to replay a token from anywhere else.
- **For an individual:** you are mostly relying on *not installing* untrusted
  extensions and on your providers having deployed binding and continuous
  evaluation server-side. There is no client-side toggle that neutralizes
  this today.

Auth-time strength — passwords, MFA, FIDO2, passkeys — is necessary but does
not touch this attack. The controls that do are the ones that act on the
session *after* login.
