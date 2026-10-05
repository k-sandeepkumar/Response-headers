# HTTP Response Headers — VAPT Reference Guide

> **Scope:** Practical reference for analysing HTTP **response** headers during authorized Vulnerability Assessment and Penetration Testing (VAPT).
> **Conventions:** All hosts are reserved example domains (`example.com`, `trusted.example`, `evil.example`). All tokens/cookies are redacted placeholders. Only test systems you are explicitly authorized to test.

## Classification Legend

| Label | Meaning |
|---|---|
| ✅ **Secure** | Implementation meets current best practice for typical deployments |
| 🟡 **Weak** | Present but offers reduced protection; a hardening gap, not directly exploitable on its own |
| 🔴 **Vulnerable** | Configuration that enables (or directly leads to) a demonstrable attack when conditions are met |
| 🔵 **Context-dependent** | Safe or unsafe depending on architecture, data sensitivity, or browser behavior |
| ⚪ **Deprecated / Legacy** | Obsolete header or behavior; do not rely on it as a primary control |

## Table of Contents

1. [Introduction](#1-introduction)
2. [Response Header Master Checklist](#2-response-header-master-checklist)
3. [Value Combinations — How to Read Them](#3-value-combinations--how-to-read-them)
4. [HSTS (Strict-Transport-Security)](#4-hsts-strict-transport-security)
5. [Content-Security-Policy](#5-content-security-policy)
6. [X-Content-Type-Options](#6-x-content-type-options)
7. [X-Frame-Options](#7-x-frame-options)
8. [Referrer-Policy](#8-referrer-policy)
9. [Permissions-Policy](#9-permissions-policy)
10. [Set-Cookie](#10-set-cookie)
11. [CORS Headers](#11-cors-headers)
12. [Cache-Control and Caching](#12-cache-control-and-caching)
13. [Information Disclosure Headers](#13-information-disclosure-headers)
14. [Content Headers](#14-content-headers)
15. [Redirection (Location)](#15-redirection-location)
16. [Proxy / Forwarded Headers](#16-proxy--forwarded-headers)
17. [Rate-Limiting Headers](#17-rate-limiting-headers)
18. [Authentication Headers](#18-authentication-headers)
19. [Legacy / Deprecated Headers](#19-legacy--deprecated-headers)
20. [VAPT Testing Methodology](#20-vapt-testing-methodology)
21. [Burp Suite Checklist](#21-burp-suite-checklist)
22. [curl Commands](#22-curl-commands)
23. [Vulnerability Classification](#23-vulnerability-classification)
24. [Finding Format (Report Template)](#24-finding-format-report-template)
25. [Mitigation Master Table](#25-mitigation-master-table)
26. [Secure Baseline](#26-secure-baseline)
27. [Quick VAPT Checklist](#27-quick-vapt-checklist)
28. [Important Accuracy Rules](#28-important-accuracy-rules)

---

## 1. Introduction

### 1.1 What are HTTP response headers?

HTTP response headers are `Name: value` metadata lines sent by a server (or intermediary such as a CDN, reverse proxy, load balancer, or WAF) before the response body. They instruct the client — usually a browser — how to handle the content: how to cache it, which origins may read it, how to store cookies, which scripts may run, whether it may be framed, and so on.

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
Set-Cookie: session=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/
Cache-Control: no-store
Server: nginx
```

### 1.2 Why they matter in VAPT

- Many are **browser-enforced security controls**. They are mostly **defense-in-depth**: they limit the *impact* of other bugs (XSS, clickjacking, MITM, data leakage) rather than being the bug themselves.
- Some are **directly security-relevant**: `Set-Cookie`, CORS headers, `Location`, `Cache-Control` on sensitive responses, and parsing-related headers (`Transfer-Encoding`, `Content-Length`) can be the root cause of real vulnerabilities.
- Some leak **reconnaissance data** (software versions, internal hostnames, request IDs, internal IPs).
- They reveal **architecture**: CDN/WAF/proxy layers, caching layers, API gateways, rate-limit design.

### 1.3 How attackers abuse missing or misconfigured headers

| Misconfiguration | Typical abuse (requires additional conditions) |
|---|---|
| No/weak HSTS | SSL-stripping / downgrade by an on-path attacker on first or expired visit |
| No/weak CSP | An existing XSS or injection becomes easier to exploit and exfiltrate from |
| No framing protection | Clickjacking / UI redressing on sensitive state-changing pages |
| Permissive CORS (reflected origin + credentials) | Cross-origin reads of authenticated data from an attacker site |
| Cookie flag gaps | Cookie theft via XSS (no `HttpOnly`), network interception (no `Secure`), CSRF (weak `SameSite`) |
| Sensitive responses cached | Data exposure on shared computers, shared proxies, or CDN cache poisoning/deception |
| Open redirect in `Location` | Phishing, OAuth token/code theft chains |
| Trusting client `X-Forwarded-*` | IP-based ACL/rate-limit bypass, log spoofing, host-header poisoning |
| Version disclosure | Faster CVE targeting (low severity on its own) |

### 1.4 Request headers vs. response headers

| Aspect | Request headers | Response headers |
|---|---|---|
| Sent by | Client → Server | Server → Client |
| Controlled by | Client / attacker (fully attacker-controlled in a direct test) | Server, framework, proxy, CDN |
| Examples | `Host`, `Origin`, `Cookie`, `Authorization`, `User-Agent`, `X-Forwarded-For` | `Set-Cookie`, `Content-Security-Policy`, `Cache-Control`, `Location`, `Server` |
| VAPT role | **Inputs** to fuzz/manipulate (e.g., `Origin`, `Host`, `X-Forwarded-Host`) | **Outputs** to evaluate for misconfiguration and reflection |
| Note | Some headers exist in both directions (`Content-Type`, `Content-Length`, `Transfer-Encoding`, `Cache-Control`, `Via`). | Response headers can **reflect** request headers (e.g., `Origin` → `Access-Control-Allow-Origin`) — a common bug source. |

### 1.5 Inspecting response headers

#### Burp Suite
- **Proxy → HTTP history**: select a request, open the **Response** tab (Pretty/Raw/Hex). Use filters (MIME type, status) and search for header names.
- **Repeater**: resend with modified request headers (`Origin`, `Host`, `X-Forwarded-*`, `Cookie`) and compare responses.
- **Inspector** panel: view/edit headers in a structured form.
- **Logger / Organizer**: bulk-filter across tools; use Logger filters such as `Response header contains "Server"`.
- **Scanner** (Professional): passive checks flag missing/weak headers and cookie flags; always validate manually.

#### Browser DevTools
- **Network** tab → click a request → **Headers** → *Response Headers*. Tick *Raw* for exact formatting.
- **Application → Cookies** shows parsed cookie attributes (Secure, HttpOnly, SameSite, Domain, Path, Expires).
- **Console** shows CSP violations, CORS errors, mixed-content and framing blocks — these confirm that browser enforcement is actually happening.
- **Security** panel (Chromium) summarises HTTPS/certificate state.

#### curl
```bash
curl -I https://example.com                       # HEAD request (headers only)
curl -s -D - -o /dev/null https://example.com     # GET request, dump headers, discard body
```
> `HEAD` responses may differ from `GET` responses (some apps/CDNs behave differently). Prefer `-D -` with GET for accurate results.

#### Nmap (where applicable)
```bash
nmap -p 80,443 --script http-headers example.com
nmap -p 80,443 --script http-server-header example.com
nmap -p 80,443 --script http-cookie-flags example.com
nmap -p 80,443 --script http-cors example.com
nmap -p 80,443 --script http-methods example.com
nmap -p 80,443 --script http-security-headers example.com   # only if installed (third-party script)
```
> Nmap's built-in scripts cover raw headers, server banners, cookie flags, CORS and methods. They are **not** a substitute for manual analysis of CSP, cache logic, or CORS reflection.

---

## 2. Response Header Master Checklist

> Legend: ✅ secure / 🟡 weak / 🔴 vulnerable / 🔵 context-dependent / ⚪ deprecated.
> "Risk" is **typical, contextual** — never assume High/Critical for a missing header on its own.

### 2.1 Browser-security headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Strict-Transport-Security` | Force HTTPS for host (and optionally subdomains) | Prevents protocol downgrade / SSL-stripping on repeat visits | `max-age=31536000; includeSubDomains` (+ `preload` only after readiness checks) | Missing; `max-age` very short (e.g., 300); `max-age=0` (disables); sent only over HTTP (ignored) | Low–Medium (needs on-path attacker) | Add header on all HTTPS responses; redirect HTTP→HTTPS; raise max-age gradually |
| `Content-Security-Policy` | Restrict resource loading / script execution / framing / form targets | Strong XSS & injection impact reducer; clickjacking via `frame-ancestors` | Nonce/hash-based `script-src`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors`, `form-action` | Missing; `default-src *`; `'unsafe-inline'`/`'unsafe-eval'` in `script-src`; `data:` in `script-src`; broad CDN hosts | Low–High (depends on presence of XSS) | Move to strict CSP; use Report-Only to iterate |
| `X-Content-Type-Options` | Disable MIME sniffing | Prevents content-type confusion (e.g., uploaded text treated as script) | `nosniff` | Missing; invalid value (e.g., `nosniff;` variants or `1`) | Low | Set `nosniff` and correct `Content-Type` |
| `X-Frame-Options` | Control framing (legacy) | Clickjacking defense | `DENY` or `SAMEORIGIN`; prefer CSP `frame-ancestors` | Missing (with no `frame-ancestors`); `ALLOW-FROM` (obsolete) | Low–Medium | Use `frame-ancestors`; keep XFO as fallback |
| `Referrer-Policy` | Control `Referer` leakage | Prevents URL/query leakage to third parties | `strict-origin-when-cross-origin` or stricter | `unsafe-url`; `no-referrer-when-downgrade` with sensitive URLs | Low | Use stricter policy; keep secrets out of URLs |
| `Permissions-Policy` | Enable/disable browser features per origin/frame | Limits abuse of camera, mic, geolocation etc. by injected/embedded content | Deny unused features: `camera=(), microphone=(), geolocation=()` | `*` for sensitive features; none set where third-party iframes are embedded | Low | Deny by default; allow explicit origins |
| `Cross-Origin-Opener-Policy` (COOP) | Isolate browsing context group | Mitigates cross-window attacks / XS-Leaks; enables cross-origin isolation | `same-origin` (or `same-origin-allow-popups` if popups needed) | `unsafe-none`; missing on sensitive apps | Low | Set COOP; test OAuth/payment popup flows |
| `Cross-Origin-Resource-Policy` (CORP) | Restrict who can load a resource | Mitigates Spectre-style and cross-origin resource inclusion leaks | `same-origin` / `same-site` for private resources | `cross-origin` on private/authenticated resources | Low | Set restrictive CORP on sensitive resources |
| `Cross-Origin-Embedder-Policy` (COEP) | Require embedded resources to opt in | Needed (with COOP) for cross-origin isolation | `require-corp` or `credentialless` where isolation is needed | `unsafe-none` where isolation is required | Informational | Deploy only if app needs isolation (SharedArrayBuffer, etc.) |
| `Clear-Site-Data` | Instruct browser to clear cache/cookies/storage | Cleans client data on logout | On logout: `"cache", "cookies", "storage"` | Absent at logout on sensitive apps | Low | Send on logout response |
| `X-XSS-Protection` ⚪ | Legacy XSS auditor toggle | Removed from modern browsers; legacy filter had side channels | Omit, or `0` | `1; mode=block` relied on as a control | Informational | Rely on CSP + output encoding |
| `X-Permitted-Cross-Domain-Policies` | Restrict Flash/PDF cross-domain policy files | Legacy plugin control | `none` | `all` | Informational | Set `none` or omit |
| `X-Download-Options` ⚪ | IE-only: prevent "Open" on downloads | Legacy IE behavior | `noopen` (legacy) | — | Informational | Not relevant for modern browsers |

### 2.2 Cache headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Cache-Control` | Cache directives for browser & shared caches | Sensitive data stored in browser/proxy/CDN caches | Sensitive: `no-store`; private user data: `private, no-cache` (or `no-store`); static: `public, max-age=..., immutable` | Missing/`public` on authenticated or PII responses | Low–High (data-dependent) | Set `no-store` on sensitive responses; configure CDN to respect it |
| `Pragma` ⚪ | HTTP/1.0 cache directive | Legacy; mostly ignored by modern clients | `no-cache` (only for HTTP/1.0 compat) | Relying on it alone | Informational | Use `Cache-Control` |
| `Expires` | Absolute expiry date | Legacy freshness; overridden by `Cache-Control` | `0` or past date on sensitive pages (as fallback) | Far-future on dynamic/sensitive pages | Low | Prefer `Cache-Control` |
| `ETag` | Validator for conditional requests | Can leak inode/size (old Apache), enable cross-user tracking | Strong/opaque ETag; avoid per-user fingerprinting | Inode-based ETag; ETag used as tracking ID | Informational | Disable inode-based ETags |
| `Last-Modified` | Validator / timestamp | Minor info leak of update times | Fine for static | Leaks timing on sensitive resources | Informational | Optional removal |
| `Age` | Seconds object has been in shared cache | Reveals caching layer; useful for cache poisoning/deception research | Informational | Indicates unexpected caching of dynamic content | Informational | Verify cache rules |
| `Vary` | Declares request headers affecting the response | Prevents cache poisoning/mix-up; required with reflected `Origin` | `Vary: Origin` (CORS), `Vary: Accept-Encoding`, `Cookie` where needed | Missing `Vary: Origin` with dynamic ACAO | Low–Medium | Add proper `Vary` |

### 2.3 Cookie / session headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Set-Cookie` | Set cookie + attributes | Session theft, CSRF, scope leakage | `Secure; HttpOnly; SameSite=Lax` (or `Strict`); narrow `Path`; no `Domain` unless needed; `__Host-` prefix | No `Secure`; no `HttpOnly` on session cookie; `SameSite=None` without `Secure`; broad `Domain`; long-lived session | Low–High (context) | Set all flags; short lifetime; rotate on login |

### 2.4 CORS headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Access-Control-Allow-Origin` | Which origin may read the response | Cross-origin data theft if too broad | Exact origin from server-side allowlist; `*` only for public, non-credentialed data | Reflected arbitrary `Origin`; `null`; regex/suffix bypasses | Medium–High with credentials | Strict allowlist + `Vary: Origin` |
| `Access-Control-Allow-Credentials` | Allow cookies/auth on cross-origin | Makes authenticated data readable cross-origin | `true` only with a specific trusted origin | `true` with reflected/`null`/overly broad origin | High (when paired with reflection) | Remove or restrict |
| `Access-Control-Allow-Methods` | Allowed methods in preflight | Expands state-changing surface | Minimal set (`GET, POST`) | `*` or `DELETE, PUT` unnecessarily | Low | Limit to needed |
| `Access-Control-Allow-Headers` | Allowed request headers | Allows custom/auth headers cross-origin | Explicit list | `*` with credentials sensitivity (note: `*` is not honored for credentialed requests) | Low | Explicit allowlist |
| `Access-Control-Expose-Headers` | Response headers readable by JS | Could expose tokens/internal headers | Only required headers | Exposing `Set-Cookie`-like tokens/auth headers | Low | Minimize |
| `Access-Control-Max-Age` | Preflight cache duration | Long caching keeps stale policy | `600`–`7200` (browsers cap values) | Excessively long | Informational | Keep moderate |

### 2.5 Information disclosure headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Server` | Identifies server software | Recon aid | Generic or removed (`Server: nginx` / omitted) | Full version + modules (`Apache/2.4.x (Unix) OpenSSL/...`) | Informational–Low | `ServerTokens Prod`, `server_tokens off` |
| `X-Powered-By` | Identifies framework/language | Recon aid | Remove | `PHP/8.x`, `Express`, `ASP.NET` | Informational–Low | Disable in framework config |
| `X-AspNet-Version` | ASP.NET version | Recon aid | Remove | Present with version | Informational–Low | `<httpRuntime enableVersionHeader="false"/>` |
| `X-AspNetMvc-Version` | ASP.NET MVC version | Recon aid | Remove | Present | Informational–Low | `MvcHandler.DisableMvcResponseHeader = true` |
| `X-Generator` | CMS/generator name | Recon aid | Remove | `Drupal 10`, `WordPress x.y` | Informational–Low | Remove via config/plugin |
| `Via` / `X-Cache` / `X-Served-By` | Proxy/CDN tracing | Reveals internal hops/hostnames | Strip internal values at edge | Internal hostnames/IPs | Informational–Low | Normalize at edge |

### 2.6 Content & parsing headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Content-Type` | MIME type + charset | Wrong type → XSS/sniffing/MIME confusion | Accurate type + charset; e.g., `application/json; charset=utf-8` | `text/html` for JSON/user content; missing charset on HTML; user-controlled | Low–High (context) | Correct types + `nosniff` |
| `Content-Disposition` | Inline vs download, filename | Forces download of untrusted files; filename injection | `attachment; filename="report.pdf"` for user files | `inline` for user-uploaded HTML/SVG; unsanitized filename | Low–High | Serve untrusted files as `attachment` from a separate origin |
| `Content-Encoding` | Compression applied | Compression side-channels (BREACH) where secrets reflect | `gzip`/`br` for non-secret-reflecting bodies | Compressing responses mixing secrets + attacker input (BREACH) | Low | CSRF-token masking; separate secrets; rate limit |
| `Content-Length` | Body length in bytes | Request/response smuggling when inconsistent with `Transfer-Encoding` | Consistent with body; single value | Duplicate/conflicting values | Medium–High (if smuggling confirmed) | Normalize at edge; use HTTP/2 end-to-end |
| `Transfer-Encoding` | Body framing (`chunked`) | HTTP desync (CL.TE/TE.CL/TE.TE) | Consistent front/back-end parsing | Obfuscated `Transfer-Encoding` accepted by one tier | High (if confirmed) | Patch proxies; reject ambiguous requests |
| `Content-Range` | Partial content range | Info disclosure via range abuse; DoS (many ranges) | Only for range-capable resources | Unlimited multi-range requests | Low | Limit ranges |
| `Link` | Resource hints / relations | Can reveal internal URLs/preload hosts | Public URLs only | Internal endpoints | Informational | Review |

### 2.7 Redirect, proxy & transport headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `Location` | Redirect target | Open redirect; downgrade to HTTP; secrets in URL | Same-origin relative or allowlisted absolute HTTPS URLs | User-controlled target; `http://` target; tokens in query | Low–High (chains) | Allowlist destinations |
| `Forwarded` | Standard proxy info (RFC 7239) | Spoofing if client-supplied is trusted | Set only by trusted proxy; strip inbound | Client-supplied trusted by app | Medium | Overwrite at edge |
| `X-Forwarded-For` | Client IP chain | IP-based controls, logging, rate limit bypass | Appended by trusted proxy; parse from trusted hop only | Leftmost value trusted blindly | Medium | Trusted-proxy config |
| `X-Forwarded-Host` | Original host | Host-header poisoning, password-reset poisoning, cache poisoning | Ignore unless from trusted proxy | App builds links from it | Medium–High | Use fixed canonical host |
| `X-Forwarded-Proto` | Original scheme | Redirect loops/mixed content; HTTPS decisions | Set by trusted proxy | Client-controlled | Low–Medium | Overwrite at edge |
| `X-Real-IP` | Client IP (nginx convention) | Same spoofing risk as XFF | Set by edge only | Client-supplied accepted | Medium | Overwrite at edge |
| `Alt-Svc` | Advertise alternative services (HTTP/3) | Reveals alt endpoints/ports | Intentional endpoints only | Unexpected hosts/ports | Informational | Review |

### 2.8 Authentication, API & operational headers

| Header | Purpose | Security Relevance | Recommended Configuration | Vulnerable/Weak Configuration | Risk | Mitigation |
|---|---|---|---|---|---|---|
| `WWW-Authenticate` | Auth challenge with 401 | Reveals scheme/realm; Basic over HTTP exposes creds | `Bearer realm="api"`; Basic only over HTTPS | `Basic` over HTTP; verbose errors | Low–High | HTTPS only; minimal error detail |
| `Proxy-Authenticate` | Proxy auth challenge with 407 | Proxy exposure/enumeration | Authenticated proxy over TLS | Basic over cleartext | Low | Harden proxy |
| `Retry-After` | Delay before retry (429/503/3xx) | Rate-limit behavior; informs attackers/clients | Seconds or HTTP-date | Missing on 429 (usability) | Informational | Include with 429/503 |
| `RateLimit-Limit` / `-Remaining` / `-Reset` | Standardized rate-limit info (IETF draft) | Informational; reveals thresholds | Present for client UX | Treated as proof of enforcement | Informational | Verify enforcement by testing |
| `X-RateLimit-Limit` / `-Remaining` / `-Reset` | De-facto rate-limit headers | Same as above | Same | Same | Informational | Same |
| `Deprecation` | Signals API deprecation (RFC 9745) | Lifecycle awareness; old versions may lack fixes | Use with `Link: rel="deprecation"` | Deprecated versions still exposed | Informational | Retire old versions |
| `Sunset` | API retirement date (RFC 8594) | Same | HTTP-date | Past sunset date but still live | Informational | Decommission |
| `Traceparent` | W3C trace context | Can expose trace IDs/internal topology | Fine internally | Leaks internal tracing to clients | Informational | Strip at edge if undesired |
| `X-Request-ID` | Request tracking ID | Correlation; may reveal sequential IDs/internal naming | Random UUID | Predictable/sequential or reflecting unsanitized input (log/header injection) | Informational | Generate server-side |
| `X-Correlation-ID` | Cross-service correlation | Same as above | Random UUID | Echoes untrusted client value unsanitized | Informational | Validate/sanitize |

### 2.9 Other relevant response headers

| Header | Purpose | Security Relevance | Recommended | Weak/Vulnerable | Mitigation |
|---|---|---|---|---|---|
| `Content-Security-Policy-Report-Only` | Test CSP without enforcing | Not enforcing — no protection | Use during rollout only | Left as only CSP in production | Promote to enforced CSP |
| `Report-To` / `NEL` | Reporting endpoints / network error logging | Telemetry; data sent to third parties | Trusted collector | Untrusted endpoints | Review |
| `Timing-Allow-Origin` | Exposes resource timing | Timing side-channels | Restricted origins | `*` on sensitive endpoints | Restrict |
| `Origin-Agent-Cluster` | Origin-keyed agent clustering | Isolation hardening | `?1` | — | Optional |
| `Accept-Ranges` | Range support | Range abuse | `bytes` only if needed | `bytes` on all dynamic endpoints | Limit |
| `Server-Timing` | Backend timing metrics | Reveals backend internals, timing side-channel | Remove in production | Verbose DB/service timings | Remove |
| `Public-Key-Pins` ⚪ | HPKP (removed) | Removed from browsers; risk of self-DoS | Do not use | Present | Remove |
| `Expect-CT` ⚪ | Certificate Transparency enforcement (obsolete) | Browsers now enforce CT by default | Do not use | Present | Remove |
| `Feature-Policy` ⚪ | Predecessor of Permissions-Policy | Deprecated | Use `Permissions-Policy` | Only Feature-Policy | Migrate |
| `X-DNS-Prefetch-Control` | DNS prefetch toggle | Minor privacy | `off` (optional) | — | Optional |
| `Refresh` | Non-standard redirect | Can act as open-redirect sink | Avoid | User-controlled | Use `Location` with validation |
| `Set-Cookie2` ⚪ | Obsolete cookie header | Ignored | Do not use | Present | Remove |
| `Access-Control-Allow-Private-Network` | Private Network Access preflight opt-in | Exposes intranet resources to public sites | Only for intended public→private access | `true` broadly | Restrict |

---

## 3. Value Combinations — How to Read Them

Sections 4–19 give, for each important header: **Purpose → Values → Secure → Weak → Vulnerable (where applicable) → Risk → Mitigation**. Each combination is classified using the legend above. A value is only labelled 🔴 *Vulnerable* when it enables a demonstrable attack under stated conditions; otherwise it is 🟡 *Weak* or 🔵 *Context-dependent*.

> **Key principle:** Response headers are mostly **browser-enforced**. A header that is missing or weak rarely proves exploitation by itself — it removes a safety net. Always pair header review with functional and exploitability testing.

---

## 4. HSTS (Strict-Transport-Security)

**Purpose:** Tells the browser to access the host **only via HTTPS** for a period of time, upgrading `http://` attempts internally (307) before any network request.

### 4.1 Directives

| Directive | Meaning | Notes |
|---|---|---|
| `max-age=<seconds>` | Duration the browser remembers the HTTPS-only rule | Refreshed on every HTTPS response. `0` deletes the policy. |
| `includeSubDomains` | Applies policy to all subdomains | Breaks any subdomain that cannot serve valid HTTPS. |
| `preload` | Signals consent to be included in browser preload lists | Not part of the spec itself; consumed by the preload list submission process. Requires `max-age` ≥ 31536000, `includeSubDomains`, and `preload`. |

### 4.2 Configuration combinations

| Configuration | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| *(header missing)* on an HTTPS site | 🟡 Weak (defense-in-depth gap) | No browser-enforced HTTPS pinning; first request to `http://` can be intercepted | Low–Medium (requires on-path attacker; higher on public Wi-Fi/high-risk apps) | Add HSTS; ensure HTTP→HTTPS redirect |
| `max-age=0` | 🔵 Context-dependent (HSTS **disabled**) | Instructs browser to delete the stored policy. Intentional during decommissioning/rollback; a misconfiguration on a production HTTPS app | Equivalent to missing HSTS | Use positive max-age on production sites |
| `max-age=300` | 🟡 Weak | 5-minute window; protection lapses quickly. Acceptable only as initial rollout step | Low | Increase gradually to ≥ 1 year |
| `max-age=86400` | 🟡 Weak / 🔵 rollout | 1 day. Fine as a staged rollout, insufficient long-term | Low | Increase to 31536000 |
| `max-age=31536000` | ✅ Secure (host only) | 1 year; subdomains not covered | Low residual (subdomain downgrade/cookie injection) | Add `includeSubDomains` if all subdomains support HTTPS |
| `max-age=31536000; includeSubDomains` | ✅ Secure | Covers host and all subdomains; common baseline | Low | Verify every subdomain (including internal/legacy) supports HTTPS first |
| `max-age=31536000; preload` | 🟡 Weak / ❌ Not preload-eligible | `preload` without `includeSubDomains` fails list requirements; preload flag is meaningless until submitted | Low | Add `includeSubDomains` or remove `preload` |
| `max-age=31536000; includeSubDomains; preload` | ✅ Secure (strongest) / 🔵 operationally risky | Eligible for preload list; protects first visit. **Hard to reverse** (removal takes months) | Low (security) / High (availability if HTTP-only subdomains exist) | Audit all subdomains; test staged max-age; submit only deliberately |
| `max-age=-1` / `max-age=abc` / missing value | 🟡 Weak (invalid) | Browsers ignore invalid headers | Equivalent to missing | Correct syntax |
| HSTS returned only over HTTP | ⚪ Ineffective | Browsers **ignore** HSTS received over plain HTTP | Equivalent to missing | Send over HTTPS |

### 4.3 Explanations

- **Downgrade protection:** After one valid HTTPS response with HSTS, the browser rewrites `http://example.com` to `https://example.com` locally, so an on-path attacker cannot strip TLS on later visits. It also blocks click-through of certificate errors for that host.
- **First-visit limitation (TOFU):** HSTS only works *after* the browser has seen the header. The first-ever (or post-expiry) visit over HTTP can still be intercepted. **Preload lists** close this gap because browsers ship with the domain pre-registered.
- **`includeSubDomains` impact:** Prevents attacker-controlled HTTP on subdomains from setting/overwriting cookies scoped to the parent domain. But any subdomain without valid HTTPS becomes unreachable.
- **Preload considerations:** Preload inclusion is effectively long-lived. Removal requires a list update that ships in browser releases, taking months. Never preload without confirming all current *and future* subdomains support HTTPS.
- **Why `max-age=0` disables HSTS:** A zero lifetime expires the policy immediately; the browser drops the entry. That is deliberate in the spec as a rollback mechanism.
- **Why blindly adding `preload` is dangerous:** If any subdomain (intranet tools, legacy dev hosts, mail autodiscover, vendor CNAMEs) lacks HTTPS, it becomes inaccessible for all preloaded browsers and cannot be quickly fixed.

### 4.4 Examples

```http
# ✅ Secure
Strict-Transport-Security: max-age=31536000; includeSubDomains

# ✅ Strongest (after full subdomain audit)
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# 🟡 Weak
Strict-Transport-Security: max-age=300

# 🔵 Disabled / misconfigured on production
Strict-Transport-Security: max-age=0
```

### 4.5 Testing & mitigation

```bash
curl -s -D - -o /dev/null https://example.com | grep -i strict-transport
curl -s -D - -o /dev/null http://example.com            # expect 301/308 to https://
```
**Mitigation:** Redirect HTTP→HTTPS, send HSTS on every HTTPS response (including errors/redirects), roll out in stages, then consider preload.

---

## 5. Content-Security-Policy

**Purpose:** Declares which sources a page may load/execute and where it may be framed or submit forms. Primarily a **mitigation for XSS/injection impact** and clickjacking (`frame-ancestors`). CSP is **defense-in-depth** — a missing CSP is not itself an XSS vulnerability.

### 5.1 Directives

| Directive | Controls | Fallback to `default-src`? |
|---|---|---|
| `default-src` | Fallback for most fetch directives | — |
| `script-src` | JS sources (inline, eval, external) | Yes |
| `style-src` | CSS sources | Yes |
| `img-src` | Images | Yes |
| `font-src` | Fonts | Yes |
| `connect-src` | `fetch`, XHR, WebSocket, EventSource | Yes |
| `frame-src` | Nested browsing contexts (iframes) this page embeds | Yes (via `child-src`) |
| `frame-ancestors` | Who may **embed this page** (anti-clickjacking) | **No** |
| `object-src` | `<object>`, `<embed>`, plugins | Yes |
| `base-uri` | Allowed `<base href>` | **No** |
| `form-action` | Form submission targets | **No** |
| `media-src` | `<audio>`, `<video>` | Yes |
| `worker-src` | Workers / SharedWorkers / ServiceWorkers | Yes |
| `manifest-src` | Web app manifest | Yes |
| `upgrade-insecure-requests` | Upgrade subresource HTTP→HTTPS | n/a |
| `block-all-mixed-content` | ⚪ Deprecated; superseded by browser default blocking + `upgrade-insecure-requests` | n/a |
| `report-uri` | ⚪ Deprecated reporting endpoint (still widely used) | n/a |
| `report-to` | Reporting API group name (defined via `Reporting-Endpoints`/`Report-To`) | n/a |

**Source keywords:** `'self'`, `'none'`, `'unsafe-inline'`, `'unsafe-eval'`, `'strict-dynamic'`, `'nonce-<base64>'`, `'sha256-<hash>'`, scheme sources (`https:`, `data:`, `blob:`), host sources, `*`.

> `frame-ancestors`, `sandbox`, and `report-uri` are **not** supported via `<meta http-equiv>` CSP; use the HTTP header.
> If both CSP `frame-ancestors` and `X-Frame-Options` are present, modern browsers prefer `frame-ancestors`.

### 5.2 Combinations

| Policy | Classification | Why | Risk | Mitigation |
|---|---|---|---|---|
| *(missing)* | 🟡 Weak (defense-in-depth gap) | No mitigation layer if XSS exists | Low–High depending on XSS presence | Deploy CSP |
| `default-src *` | 🔴/🟡 Vulnerable-in-effect (non-protective) | Allows loading/executing from any origin; essentially no restriction (note: `*` doesn't match `data:`/`blob:`/inline but is still permissive) | Medium with XSS present | Replace with `'self'` + explicit allowlist |
| `default-src 'self'` | ✅ Secure baseline (not complete) | Same-origin resources only; blocks inline scripts/eval by default. Missing `object-src`/`base-uri`/`frame-ancestors`/`form-action` explicit control (object-src falls back; the others don't) | Low | Add `base-uri 'self'; form-action 'self'; frame-ancestors 'none'` |
| `default-src 'self'; script-src 'self'` | ✅ Secure | Scripts only from same origin; inline blocked. Caveat: JSONP/upload endpoints on same origin can be abused | Low | Ensure no user-controlled JS served from origin |
| `default-src 'self'; script-src 'unsafe-inline'` | 🔴 Vulnerable-in-effect | Replaces `'self'` for scripts and permits inline scripts → no XSS protection (and **blocks** same-origin external scripts) | High if XSS exists | Use nonces/hashes; remove `'unsafe-inline'` |
| `default-src 'self'; script-src 'self' 'unsafe-inline'` | 🟡 Weak | Inline XSS payloads execute; CSP offers little against reflected/stored XSS | Medium–High with XSS | Migrate to nonce/hash + `'strict-dynamic'` |
| `default-src 'self'; script-src 'unsafe-eval'` | 🔴/🟡 Weak–Vulnerable | Permits `eval()`, `Function()`, string `setTimeout`; enables DOM-XSS gadgets (and blocks same-origin external scripts as `'self'` is absent) | Medium | Remove `eval` use; refactor libraries |
| `script-src 'self' 'unsafe-eval'` | 🟡 Weak | eval-based injection sinks work | Medium | Remove `unsafe-eval` |
| `default-src 'self'; object-src 'none'; base-uri 'self'` | ✅ Secure (good baseline) | Blocks plugins, prevents `<base>` hijacking | Low | Add `frame-ancestors`, `form-action` |
| `script-src 'self' data:` | 🔴 Vulnerable-in-effect | `data:` URIs allow executing attacker-supplied script | High with injection | Remove `data:` from `script-src` |
| `script-src 'self' blob:` | 🟡 Weak | Blob URLs can host attacker-created script if a script can be created | Medium | Avoid unless required |
| `script-src https:` / `script-src *.cdn.example` / broad CDNs | 🟡 Weak | Any HTTPS host / JSONP / AngularJS gadget on allowed CDN can bypass | Medium | Use nonces/hashes; avoid broad hosts |
| `script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'` | ✅ Secure (modern strict CSP) | Per-response nonces; trusted scripts can load children | Low | Ensure nonce is cryptographically random per response |
| `img-src * data:` | 🔵 Context-dependent | Images allow exfiltration channel (via query strings) but rarely script execution | Low | Restrict if sensitive pages |
| `object-src` missing (with no `default-src`) | 🟡 Weak | Legacy plugin vectors | Low | `object-src 'none'` |
| `base-uri` missing | 🟡 Weak | Attacker injecting `<base>` can redirect relative script URLs (esp. with nonce-less/`strict-dynamic` policies) | Low–Medium | `base-uri 'self'` or `'none'` |
| `frame-ancestors *` or missing | 🟡/🔵 | Page can be framed by anyone (clickjacking) | Low–Medium | `frame-ancestors 'none'` or `'self'` |
| `frame-ancestors 'self'` | ✅ Secure (for same-origin framing needs) | Only same-origin may embed | Low | — |
| `frame-ancestors 'none'` | ✅ Secure | No framing at all | Low | — |
| `frame-ancestors https://partner.example` | 🔵 Context-dependent | Allows trusted partner embeds | Low | Maintain allowlist |
| `upgrade-insecure-requests` | ✅ Hardening | Upgrades mixed content subresources | Low | — |
| `report-uri /csp-report` | ⚪ Legacy | Still works; prefer `report-to` | n/a | Add `report-to` |
| `Content-Security-Policy-Report-Only: ...` only | 🟡 Weak | Not enforced; telemetry only | Equivalent to missing | Enforce after tuning |

### 5.3 Example policies

```http
# ✅ Strong, nonce-based
Content-Security-Policy: default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-to csp-endpoint

# 🟡 Weak
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:

# 🔴 Non-protective
Content-Security-Policy: default-src *
Content-Security-Policy: script-src 'self' data:
```

### 5.4 Testing notes

- Inspect with browser Console (violation messages) and Google CSP Evaluator-style review (manual).
- Check for bypass classes: JSONP endpoints, open redirects on allowed hosts, user-upload on `'self'`, AngularJS-style template gadgets, wildcard subdomains, `'unsafe-hashes'`.
- Distinguish **CSP weakness** (hardening finding) from **confirmed XSS** (separate, higher-severity finding); document both when both exist.
- Check *every* response type: CSP is sometimes only on the HTML shell and absent from error pages or API HTML responses.

**Mitigation:** Adopt a strict nonce/hash CSP, deploy in Report-Only first, remove `unsafe-*`, set `object-src 'none'`, `base-uri`, `form-action`, `frame-ancestors`.

---

## 6. X-Content-Type-Options

**Purpose:** Stops browsers from "sniffing" a response's MIME type and overriding the declared `Content-Type`.

**MIME sniffing:** When `Content-Type` is missing/ambiguous, browsers may inspect the body and guess. An uploaded file served as `text/plain` (or without a type) containing HTML/JS might be rendered as HTML or executed as script — enabling XSS or content-type confusion. With `nosniff`, browsers block script/style loads whose MIME type does not match (and apply stricter handling for documents).

| Value | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| `X-Content-Type-Options: nosniff` | ✅ Secure | Only valid value; disables sniffing for scripts/styles and protects against MIME confusion | Low | Keep with correct `Content-Type` |
| *(missing)* | 🟡 Weak (defense-in-depth) | Sniffing allowed; matters mostly for user-uploaded/hosted content and ambiguous types | Low (higher if untrusted content is served from the same origin) | Add `nosniff` globally |
| `X-Content-Type-Options: nosniff, nosniff` / duplicate headers | 🔵 Context-dependent | Browsers typically honor the first value; inconsistent proxies may cause confusion | Low | Single header |
| `X-Content-Type-Options: 1` / `true` / `no-sniff` / `NOSNIFF ` (invalid) | 🟡 Weak | Not recognized as `nosniff` → treated as missing | Low | Use exact `nosniff` |

```http
# ✅
X-Content-Type-Options: nosniff
# 🟡 invalid, ignored
X-Content-Type-Options: 1
```
**Testing:** Serve/upload a file with `Content-Type: text/plain` containing script; check whether execution occurs when `nosniff` is absent. A missing header is a hardening gap unless sniffing is demonstrated.

---

## 7. X-Frame-Options

**Purpose:** Controls whether the page may be embedded in `<frame>`, `<iframe>`, `<object>`, `<embed>`. Mitigates **clickjacking** (UI redressing): an attacker overlays an invisible framed victim page and tricks the user into clicking state-changing UI.

| Value | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| `X-Frame-Options: DENY` | ✅ Secure | Never framed | Low | Pair with CSP `frame-ancestors 'none'` |
| `X-Frame-Options: SAMEORIGIN` | ✅ Secure (if same-origin framing needed) | Only same-origin framing (note: historic nuance with nested frames in some browsers) | Low | Prefer `frame-ancestors 'self'` |
| `X-Frame-Options: ALLOW-FROM https://partner.example` | ⚪ Deprecated / obsolete | Not supported by modern browsers → effectively **no protection** | Low–Medium (silent failure) | Use CSP `frame-ancestors https://partner.example` |
| *(missing, no `frame-ancestors`)* | 🟡 Weak / 🔵 | Page can be framed; clickjacking possible if the page has sensitive one-click actions and the session cookie is sent in a cross-site frame (SameSite/third-party-cookie behavior matters) | Low–Medium | Add XFO/`frame-ancestors` |
| `DENY, SAMEORIGIN` (duplicate/conflicting) | 🟡 Weak | Invalid combined value — browsers may ignore it | Low | Send one value |
| `X-Frame-Options: allow` (invalid) | 🟡 Weak | Ignored | Low | Correct value |

> **Modern guidance:** CSP `frame-ancestors` is the primary control; XFO is a legacy fallback. If both are present, `frame-ancestors` takes precedence in modern browsers.
> **Exploitability note:** Clickjacking requires a framable page **and** a meaningful single-click/UI action **and** an authenticated session usable in the framed context. Static/public pages without sensitive actions are usually informational.

```http
# ✅
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
# ⚪ obsolete
X-Frame-Options: ALLOW-FROM https://partner.example
```

**PoC test (authorized):** Create a local HTML page with `<iframe src="https://example.com/account/settings">`; if the page renders, the framing protection is absent.

---

## 8. Referrer-Policy

**Purpose:** Controls how much of the originating URL is sent in the `Referer` request header. Leakage matters when URLs contain tokens, IDs, search terms, password-reset links, or internal paths.

| Value | Referer sent | Strength | Classification |
|---|---|---|---|
| `no-referrer` | Never | Strongest privacy | ✅ Secure (may break analytics/CSRF checks relying on Referer) |
| `same-origin` | Full URL same-origin only; nothing cross-origin | Very strong | ✅ Secure |
| `strict-origin` | Origin only (no path); nothing on HTTPS→HTTP | Strong | ✅ Secure |
| `strict-origin-when-cross-origin` | Full URL same-origin; origin only cross-origin; nothing on downgrade | Good balance (**browser default** in modern browsers) | ✅ Secure (recommended default) |
| `origin` | Origin only everywhere (incl. downgrade) | Moderate | 🔵 Context-dependent |
| `origin-when-cross-origin` | Full same-origin; origin cross-origin (incl. downgrade) | Moderate | 🔵 Context-dependent |
| `no-referrer-when-downgrade` | Full URL except HTTPS→HTTP | Weak (older default) | 🟡 Weak — leaks full URL cross-origin over HTTPS |
| `unsafe-url` | Always full URL, even to HTTP | Weakest | 🔴 Vulnerable if URLs hold sensitive data; otherwise 🟡 |
| *(missing)* | Browser default (usually `strict-origin-when-cross-origin`) | Browser-dependent | 🔵 Context-dependent (low severity) |

**Recommended default:** `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` / `same-origin` for sensitive apps). Rationale: preserves same-site functionality while preventing path/query disclosure cross-origin and over downgrade.

```http
# ✅
Referrer-Policy: strict-origin-when-cross-origin
# 🔴 leaks full URL including query tokens
Referrer-Policy: unsafe-url
```
**Real risk:** Only when sensitive data is in the URL (reset tokens, session IDs, OAuth codes) **and** the page loads/links to third-party resources. **Mitigation:** Keep secrets out of URLs; use a stricter policy; for reset pages use `no-referrer`.

---

## 9. Permissions-Policy

**Purpose:** Allows or denies powerful browser features for the document and embedded frames. Limits abuse by injected scripts or third-party iframes. (Replaces deprecated `Feature-Policy`.)

**Syntax:** `feature=(allowlist)` where allowlist items are `*`, `self`, `()` (none), or quoted origins.

| Feature | Meaning |
|---|---|
| `camera` | Camera access |
| `microphone` | Microphone access |
| `geolocation` | Location API |
| `fullscreen` | Fullscreen API |
| `payment` | Payment Request API |
| `usb` | WebUSB |
| `clipboard-read` | Read clipboard |
| `clipboard-write` | Write clipboard |

| Policy | Classification | Explanation |
|---|---|---|
| `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()` | ✅ Secure | Disables features the app does not use |
| `Permissions-Policy: geolocation=(self), camera=(self "https://meet.example")` | ✅ Secure / 🔵 | Least privilege; only needed origins |
| `Permissions-Policy: fullscreen=(self)` | ✅ Secure | Same-origin only |
| `Permissions-Policy: camera=*, microphone=*, geolocation=*` | 🟡 Weak / 🔴 if untrusted content embedded | Any embedded frame/origin may request sensitive features (still requires user permission prompt) |
| `Permissions-Policy: clipboard-read=*` | 🟡 Weak | Broad clipboard access policy |
| *(missing)* | 🔵 Context-dependent | Browser defaults apply (many powerful features default to `self`); matters mostly where third-party iframes are embedded |

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), fullscreen=(self)
```
**Risk:** Low. Features still require **user consent** in most browsers; the policy limits who may ask. **Mitigation:** Deny by default, allow only specific origins, review third-party embeds.

---

## 10. Set-Cookie

**Purpose:** Instructs the browser to store a cookie. Cookie attributes are the main protection for session confidentiality, integrity, and CSRF resistance.

### 10.1 Attributes

| Attribute | Meaning | Security effect |
|---|---|---|
| `Secure` | Send only over HTTPS | Prevents cleartext leakage; (browsers also refuse `Secure` cookies set from insecure origins in modern versions) |
| `HttpOnly` | Not accessible to JavaScript (`document.cookie`) | Blocks direct cookie theft via XSS |
| `SameSite=Strict` | Sent only in same-site context | Strong CSRF protection; breaks inbound cross-site navigations login state |
| `SameSite=Lax` | Sent on same-site requests and top-level safe cross-site navigations (GET) | Good CSRF baseline; modern browser default if unspecified |
| `SameSite=None` | Sent in all contexts | Required for cross-site embeds; **must** have `Secure` |
| `Domain=` | Scope to domain + all subdomains | Broader scope increases exposure (any subdomain can read/set) |
| `Path=` | Limits to URL path prefix | **Not** a security boundary (same-origin JS can read other paths via iframes) |
| `Max-Age=` | Lifetime in seconds (takes precedence over Expires) | Short for sensitive sessions |
| `Expires=` | Absolute expiry date | Omit for session cookie |
| Prefixes `__Secure-` / `__Host-` | Browser-enforced constraints | `__Host-`: Secure, `Path=/`, no `Domain` — strongest binding |

### 10.2 Combinations

| Cookie | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| `Set-Cookie: sid=<redacted>; Secure; HttpOnly; SameSite=Strict; Path=/` | ✅ Secure | Strong confidentiality + CSRF protection | Low | Check UX for cross-site navigation |
| `Set-Cookie: sid=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/` | ✅ Secure (recommended default) | Balanced | Low | Use CSRF tokens for sensitive state changes anyway |
| `Set-Cookie: __Host-sid=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/` | ✅ Secure (strongest) | Origin-bound; resists subdomain overwrite | Low | — |
| `Set-Cookie: sid=<redacted>; Secure; HttpOnly; SameSite=None` | 🔵 Context-dependent | Needed for legitimate cross-site (embedded widgets, SSO); exposed to CSRF unless other defenses exist | Low–Medium | Add CSRF tokens; use `Partitioned` (CHIPS) where appropriate |
| `Set-Cookie: sid=<redacted>; SameSite=None` (no Secure) | 🔴 Vulnerable/Invalid | Modern browsers **reject** `SameSite=None` without `Secure`; in older/other clients cookie is exposed over HTTP | Medium | Add `Secure` |
| `Set-Cookie: sid=<redacted>; HttpOnly` (no `Secure`) | 🔴 Weak–Vulnerable on HTTPS apps | Cookie can be sent over HTTP (e.g., mixed content, forced HTTP request) → interception on-path | Medium | Add `Secure`; enable HSTS |
| `Set-Cookie: sid=<redacted>; Secure` (no HttpOnly) | 🟡 Weak (for session cookies) | Readable by JS → XSS can steal it | Medium–High if XSS exists | Add `HttpOnly` |
| `Set-Cookie: theme=dark` (no flags) | 🔵 Context-dependent | Non-sensitive preference cookie; flags not critical | Informational | Flag anyway as hygiene |
| `Set-Cookie: csrf=<redacted>; Secure; SameSite=Strict` (no HttpOnly) | 🔵 Context-dependent | Double-submit CSRF cookies are often intentionally JS-readable | Low | Acceptable by design |
| `Set-Cookie: sid=<redacted>; Domain=example.com; ...` | 🔵 Context-dependent | Shared with all subdomains — risky if any subdomain is untrusted/vulnerable (XSS, takeover) | Low–Medium | Omit `Domain`; use `__Host-` |
| `Set-Cookie: sid=<redacted>; Path=/app/admin` | 🔵 | Path limits transmission only; not isolation | Informational | Don't rely on Path for security |
| Session cookie with `Max-Age=31536000` | 🟡 Weak | Long-lived session increases theft window | Low–Medium | Short idle/absolute timeouts |
| Session ID unchanged after login | 🔴 Vulnerable (session fixation) | Pre-auth ID persists post-auth | Medium–High | Regenerate on privilege change |

### 10.3 When HttpOnly/Secure/SameSite do **not** help

- **HttpOnly:** XSS can't read the cookie, but injected script can still **act as the user** (issue authenticated requests from the victim's browser, perform CSRF-like actions, read responses, scrape data). HttpOnly reduces token theft/portability, not XSS impact overall.
- **Secure:** Protects transport only; doesn't stop XSS, CSRF, or server-side session flaws. Does not apply to non-session cookies that carry no sensitive data.
- **SameSite:** Governs *cross-site* requests. Doesn't stop same-site attacks (XSS or attacks from sibling subdomains — same *site* ≠ same *origin*), nor GET-based state changes under `Lax`. `Lax+POST` quirks (Chrome's "Lax-allowing-unsafe" 2-minute window for cookies without explicit SameSite) may matter.
- **Applicability:** Always apply to session/auth cookies; for pure UI-preference cookies the practical risk is low.

**Mitigation:** Use `Secure; HttpOnly; SameSite=Lax|Strict`, `__Host-` prefix, minimal scope, short lifetimes, regeneration at login, server-side invalidation at logout (and `Clear-Site-Data` when appropriate).

---

## 11. CORS Headers

**Purpose:** CORS (Cross-Origin Resource Sharing) relaxes the browser's Same-Origin Policy so that JavaScript from origin A can read responses from origin B. **CORS is a browser-enforced relaxation, not an access-control mechanism** — non-browser clients ignore it. Server-side authorization is still required.

### 11.1 Headers

| Header | Purpose |
|---|---|
| `Access-Control-Allow-Origin` (ACAO) | Origin allowed to read response (`*`, single origin, or `null`) |
| `Access-Control-Allow-Credentials` (ACAC) | `true` lets browser include cookies/HTTP auth/client certs and expose the response |
| `Access-Control-Allow-Methods` | Methods allowed in preflight |
| `Access-Control-Allow-Headers` | Request headers allowed in preflight |
| `Access-Control-Expose-Headers` | Response headers JS may read (beyond the safelisted ones) |
| `Access-Control-Max-Age` | Preflight cache seconds (browsers cap it, e.g., Chromium ≈ 2 h) |
| `Vary: Origin` | Required whenever ACAO varies per request `Origin`, to avoid cache poisoning/mix-ups |

### 11.2 Combinations

| Response headers | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| `Access-Control-Allow-Origin: *` | 🔵 Context-dependent | Fine for **public, non-sensitive, non-credentialed** resources (CDN assets, public APIs). Problematic if the endpoint returns user-specific/internal data reachable without cookies (e.g., intranet, IP-based access) | Low (public) → Medium (private/intranet data) | Use specific origins for private data |
| `Access-Control-Allow-Origin: https://trusted.example` + `Vary: Origin` | ✅ Secure | Single trusted origin | Low | Maintain allowlist |
| `Access-Control-Allow-Origin: https://trusted.example` + `Access-Control-Allow-Credentials: true` + `Vary: Origin` | ✅ Secure (if origin truly trusted & not XSS-prone) | Credentialed cross-origin with explicit trusted origin | Low–Medium (a flaw on `trusted.example` extends to this app) | Harden trusted origin; minimal scope |
| `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` | 🟡 Misconfiguration — **not directly exploitable in browsers** | Browsers **reject** credentialed responses when ACAO is `*`; so cookies-based data is not readable. Still a misconfiguration signaling poor design and risky if code later "fixes" it by reflecting Origin | Low | Remove credentials flag or use explicit origin |
| ACAO reflects arbitrary `Origin` (e.g., `Origin: https://evil.example` → `ACAO: https://evil.example`) with `ACAC: true` | 🔴 Vulnerable | Any website can read authenticated responses | High (if sensitive data & cookie auth) | Strict server-side allowlist |
| ACAO reflects arbitrary `Origin` **without** credentials | 🟡 Weak / 🔵 | Equivalent to `*` for non-credentialed data; matters for IP/intranet-protected data | Low–Medium | Allowlist |
| `Access-Control-Allow-Origin: null` + `ACAC: true` | 🔴 Vulnerable | Sandboxed iframes, `data:` URLs, and some redirects send `Origin: null`; attacker can obtain it and read data | High (if sensitive data) | Never allow `null` |
| `Access-Control-Allow-Origin: null` (no credentials) | 🟡 Weak | Same issue for non-credentialed data | Low–Medium | Remove |
| ACAO via weak regex (e.g., `*.example.com` matching `evilexample.com`, or suffix/prefix match) | 🔴 Vulnerable | Validation bypass with attacker-controlled domain | Medium–High | Exact-match allowlist, parse origin properly |
| Trusts all subdomains (`https://*.example.com`) | 🔵 Context-dependent | Subdomain XSS or takeover → full cross-origin read | Medium | Allow only needed subdomains |
| Trusts `http://` origin while app is HTTPS | 🟡/🔴 | On-path attacker can inject script into HTTP origin | Medium | Allow HTTPS origins only |
| `Access-Control-Allow-Methods: GET, POST` | ✅ Secure (minimal) | Only needed methods | Low | — |
| `Access-Control-Allow-Methods: *` / `PUT, DELETE, PATCH` unneeded | 🟡 Weak | Wider cross-origin attack surface | Low | Minimize |
| `Access-Control-Allow-Headers: Content-Type, Authorization` | 🔵 | Needed for API; credentialed (`Authorization`) | Low | Explicit list |
| `Access-Control-Allow-Headers: *` | 🔵 | Not honored for credentialed requests; permissive otherwise | Low | Explicit list |
| `Access-Control-Expose-Headers: X-Auth-Token` | 🟡 | May expose tokens to allowed origins | Low | Minimize |
| `Access-Control-Max-Age: 86400` | 🔵 | Browsers cap value; long-cached policy delays revocation | Informational | `600` |
| Dynamic ACAO without `Vary: Origin` | 🟡 Weak | Shared cache may serve ACAO for wrong origin → breakage or leak | Low–Medium | Add `Vary: Origin` |

### 11.3 Key concepts

- **Origin reflection:** Server copies request `Origin` into ACAO. Dangerous when unconditional.
- **Arbitrary origin reflection:** No validation at all; the classic exploitable CORS bug when combined with `ACAC: true`.
- **Null origin:** Allowed explicitly or via mis-parsing; attacker can force `Origin: null` using a sandboxed iframe (`<iframe sandbox="allow-scripts" srcdoc="...">`).
- **Credentialed CORS:** Requires explicit origin (not `*`) and `ACAC: true`; request must be made with `credentials: 'include'`. Cookie `SameSite` settings also affect whether cookies are actually sent cross-site — a mitigating factor to include in severity assessment.
- **Trusted-origin allowlist:** Server-side list of exact origins (scheme + host + port).
- **Server-side origin validation:** Parse the Origin, compare against an allowlist of exact strings, reject others (omit ACAO), set `Vary: Origin`.
- **Browser behavior:** `*` + credentials is blocked; simple vs preflighted requests; `OPTIONS` handling; `fetch` mode.
- **Not a server auth control:** curl/Burp ignore CORS; CORS only limits cross-origin *reading* in browsers (CSRF is a separate topic).

### 11.4 Test examples

```bash
# Arbitrary origin reflection
curl -s -D - -o /dev/null https://api.example.com/profile \
  -H "Origin: https://evil.example" -H "Cookie: session=<redacted>"

# Null origin
curl -s -D - -o /dev/null https://api.example.com/profile -H "Origin: null"

# Regex bypass candidates
curl -s -D - -o /dev/null https://api.example.com/profile -H "Origin: https://evilexample.com"
curl -s -D - -o /dev/null https://api.example.com/profile -H "Origin: https://example.com.evil.example"

# Preflight
curl -s -D - -o /dev/null -X OPTIONS https://api.example.com/profile \
  -H "Origin: https://trusted.example" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: authorization"
```
**Exploit validation (authorized PoC):** Host a page on a controlled origin that calls `fetch('https://api.example.com/profile',{credentials:'include'})` and reads the response. A reflected ACAO + `ACAC: true` that returns sensitive data when the victim is logged in = confirmed vulnerability.

---

## 12. Cache-Control and Caching

**Purpose:** Controls caching by browsers and shared caches (CDN, reverse proxy, forward proxy).

### 12.1 Directives

| Directive | Meaning |
|---|---|
| `no-store` | **Do not store** the response anywhere (strongest for sensitive data) |
| `no-cache` | May be stored, but **must revalidate** with the origin before reuse (**does NOT mean "don't cache"**) |
| `private` | Only the end-user's browser cache may store; shared caches must not |
| `public` | Any cache may store (even if normally non-cacheable, e.g., with `Authorization`) |
| `max-age=<s>` | Freshness lifetime (all caches) |
| `s-maxage=<s>` | Freshness lifetime for shared caches (overrides `max-age`) |
| `must-revalidate` | Once stale, must revalidate; no serving stale |
| `immutable` | Won't change during freshness (static versioned assets) |
| `stale-while-revalidate` / `stale-if-error` | Serving stale during revalidation/error |

### 12.2 `no-cache` vs `no-store`

| | `no-cache` | `no-store` |
|---|---|---|
| Stored on disk/memory? | Yes (may be) | No |
| Reuse without validating? | No — must revalidate | Not applicable (not stored) |
| Suitable for secrets/PII? | Not alone (data may sit in cache) | Yes |
| Typical use | Frequently changing but cacheable content | Banking pages, tokens, PII |

### 12.3 Combinations by scenario

| Scenario | Header | Classification | Explanation |
|---|---|---|---|
| **Login page** | `Cache-Control: no-store` | ✅ | Prevents storing forms/CSRF tokens/autofill artifacts |
| Login page | `Cache-Control: public, max-age=3600` | 🔴 on shared cache with tokens / 🟡 | Cached CSRF token/page, possible cache poisoning/deception chain |
| **Banking page / account data** | `Cache-Control: no-store` (+ `Pragma: no-cache` legacy) | ✅ | Back-button/shared-computer exposure prevented |
| Banking page | `Cache-Control: no-cache` | 🟡 Weak | Revalidation required, but copy may remain stored in browser |
| Banking page | missing (heuristic caching) | 🔴 Vulnerable if sensitive content is stored/cached by shared proxy/CDN | Data exposure to later users/proxy |
| **Authenticated API responses** | `Cache-Control: private, no-store` | ✅ | |
| API (user-specific) | `Cache-Control: public, max-age=600` | 🔴 | Shared cache may serve one user's data to another |
| API (public data) | `Cache-Control: public, max-age=300, s-maxage=600` | ✅/🔵 | Appropriate for non-sensitive data |
| **Static resources** | `Cache-Control: public, max-age=31536000, immutable` (fingerprinted filenames) | ✅ | Efficient |
| Public content (blog, marketing) | `Cache-Control: public, max-age=300` | ✅ | |
| Sensitive file download | `Cache-Control: no-store`; `Content-Disposition: attachment` | ✅ | |
| `Pragma: no-cache` only | ⚪ Legacy / 🟡 | HTTP/1.0 request semantic; not reliable for responses | Use `Cache-Control` |
| `Expires: 0` / past date | 🔵 | Treated as already expired (invalid dates treated as expired) | Fallback only |

### 12.4 Risks

- Sensitive pages stored in browser history/disk cache → exposure on shared devices; Back-button replays after logout.
- Shared proxy/CDN caching authenticated responses → data leakage between users.
- **Web cache deception:** e.g., `/account/profile/x.css` cached as static while returning user data.
- **Web cache poisoning:** Unkeyed headers (`X-Forwarded-Host`) reflected into cacheable responses.
- Clarify severity: browser-cache findings are typically **Low** unless shared caches or highly sensitive data are involved.

**Mitigation:** `no-store` for sensitive responses, `private` for user-specific data, never `public` on authenticated content, configure CDN to bypass cache on `Set-Cookie`/`Authorization`, use `Vary` correctly, and send `Clear-Site-Data` on logout.

---

## 13. Information Disclosure Headers

**Headers:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator` (also `Via`, `X-Cache`, `X-Served-By`, `Server-Timing`).

| Example | Classification | Explanation |
|---|---|---|
| `Server: nginx` / `Server: Apache` | ✅ / 🔵 | Product name only; minimal and generally acceptable |
| `Server: Apache/2.4.x (Ubuntu)` | 🟡 Weak (informational) | Version + OS disclosed |
| `Server: nginx/1.x.x` | 🟡 Weak (informational) | Version disclosed |
| `Server: Microsoft-IIS/10.0` | 🔵 | Product/major version (often inferable anyway) |
| `X-Powered-By: PHP/8.x` | 🟡 Weak (informational) | Language/runtime version |
| `X-Powered-By: Express` | 🟡 | Framework disclosure |
| `X-AspNet-Version: 4.0.30319` / `X-AspNetMvc-Version: 5.2` | 🟡 | Framework version |
| `X-Generator: Drupal 10 (https://www.drupal.org)` | 🟡 | CMS fingerprint |
| `Server: cloudflare` / CDN banner | 🔵 | Architecture info; not a flaw |
| Header with **outdated, known-vulnerable version** (confirmed by testing) | 🔴 (the *outdated component* is the finding, not the header) | Report as vulnerable software with CVE evidence |

**Why version disclosure assists recon:** Attackers can map versions to known CVEs, prioritize targets, and craft exploits. It reduces attacker effort — but does **not** itself compromise the system.

**Why it is generally low severity alone:** Versions can often be fingerprinted through behavior, error pages, file paths, or TLS stacks; banners can be spoofed or stale (reverse proxies may mask backends). Removing banners is "security through obscurity" — useful friction, not a fix.

**When it becomes more relevant:**
- Version is **confirmed vulnerable** with a reachable exploit path (report the CVE-backed finding).
- Header discloses **internal hostnames, IPs, build paths, debug info** (`X-Backend-Server: app-prod-03.internal`).
- Combined with other weaknesses (default pages, exposed admin consoles).
- Compliance requirements (some standards flag banner disclosure).

> Do **not** auto-classify every `Server` header as a vulnerability. A bare product name (`Server: nginx`) is typically *not* a finding.

**Mitigation:**
```apache
# Apache
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
```
```nginx
# nginx
server_tokens off;
# proxy_hide_header X-Powered-By;  (when proxying)
```
```ini
; PHP (php.ini)
expose_php = Off
```
```xml
<!-- ASP.NET -->
<httpRuntime enableVersionHeader="false" />
<!-- IIS: remove X-Powered-By custom header; MvcHandler.DisableMvcResponseHeader = true in Global.asax -->
```
Also keep software patched — that's the real fix.

---

## 14. Content Headers

### 14.1 Content-Type

| Value | Classification | Notes |
|---|---|---|
| `Content-Type: text/html; charset=utf-8` | ✅ | Explicit charset avoids charset-based XSS |
| `Content-Type: application/json; charset=utf-8` | ✅ | Proper API type |
| `Content-Type: text/html` (no charset) | 🟡 Weak | Browser may guess encoding (legacy UTF-7-style attacks mostly historical) |
| `Content-Type: text/html` for JSON containing user input | 🔴 Vulnerable (reflected XSS in JSON endpoint) | Browser renders as HTML |
| `Content-Type: application/octet-stream` for user downloads | ✅ (with `nosniff` + attachment) | |
| `Content-Type: text/plain` for uploaded HTML without `nosniff` | 🟡/🔴 | Sniffing may allow rendering → stored XSS |
| `Content-Type: image/svg+xml` for user-uploaded SVG served inline | 🔴 (potential) | SVG can contain script; serve as attachment, sandbox, or sanitize |
| Missing `Content-Type` | 🟡 Weak | Triggers sniffing |

**MIME confusion tests:** upload polyglots, change extension vs MIME, check whether script executes via `<script src>` when `nosniff` absent; verify user-controllable Content-Type reflection.

### 14.2 Content-Disposition

| Value | Classification | Notes |
|---|---|---|
| `Content-Disposition: attachment; filename="report.pdf"` | ✅ | Forces download — safer for user-supplied content |
| `Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf` | ✅ | RFC 6266/5987 encoded filename |
| `Content-Disposition: inline` for user-uploaded HTML/SVG/XML on app origin | 🔴 Potential stored XSS | Serve from sandbox domain, or force `attachment` |
| Unsanitized filename containing CR/LF or quotes | 🔴 Header/Response splitting (modern servers usually block CRLF) | Sanitize; use encoded filename |
| Filename with path traversal (`../`) rendered client-side by tools | 🟡 | Sanitize/ignore client-supplied names |
| Reflected Download (RFD) pattern: user input in filename/extension in JSON/JSONP responses | 🔴 (rare) | Set `Content-Disposition: attachment; filename=api.txt`, validate callbacks |

### 14.3 Content-Encoding / Content-Length / Transfer-Encoding / Content-Range

| Header | Security implication | Test / Mitigation |
|---|---|---|
| `Content-Encoding: gzip/br` | **BREACH-style** compression oracle when HTTPS responses mix secrets (CSRF token) with attacker-controlled reflected text | Mask tokens per-request, limit reflection, rate limit; usually Low–Medium and context-dependent |
| `Content-Length` | Must match the actual body; conflicting lengths cause desync | Test duplicates/mismatches with proxies; patch intermediaries |
| `Transfer-Encoding: chunked` | **Request smuggling/desync** (CL.TE, TE.CL, TE.TE obfuscation) when front-end and back-end disagree | Use HTTP/2 end-to-end, disable ambiguous parsing, normalize at edge; confirm with safe timing/differential tests only in authorized scope |
| Both `Content-Length` and `Transfer-Encoding` present | 🔴 Potentially vulnerable if tiers prioritize differently | Reject such requests/responses |
| `Content-Range` / `Accept-Ranges: bytes` | Range requests can leak partial content or cause resource exhaustion (overlapping ranges) | Limit number/size of ranges |
| `HEAD` vs `GET` header mismatch | Informational; may bypass naive header scans | Test both |

> **Parsing issues are exploitability-driven:** do not report smuggling merely because both headers appear; a confirmed desync (response queue poisoning, differential response) is required.

---

## 15. Redirection (Location)

**Purpose:** Indicates the redirect target for `3xx` (and `201`) responses.

| Example | Classification | Explanation | Risk | Mitigation |
|---|---|---|---|---|
| `Location: /dashboard` | ✅ | Relative same-origin | Low | — |
| `Location: https://example.com/login` | ✅ | Fixed HTTPS destination | Low | — |
| `Location: https://app.example.com/` (allowlisted) | ✅ | Trusted external | Low | Maintain allowlist |
| `Location: <value of ?next=>` unvalidated, e.g., `?next=https://evil.example` → `Location: https://evil.example` | 🔴 Open redirect | Phishing, OAuth/SSO code/token theft (when combined with redirect_uri flaws), filter bypass chains | Low–Medium alone; High in OAuth chains | Allowlist / relative-only / signed destinations |
| `Location: //evil.example` (protocol-relative) | 🔴 | Parsed as external | Low–Medium | Normalize and reject `//`, `\`, encoded variants |
| `Location: http://example.com/...` from HTTPS page | 🟡/🔴 | HTTPS→HTTP downgrade of the next request | Low–Medium | Use `https://` or relative URL; HSTS |
| `Location: https://example.com/reset?token=<redacted>` | 🟡 | Sensitive token in URL → logs, history, Referer leakage | Medium | Use POST/fragment/short-lived one-time tokens + `Referrer-Policy` |
| `Location` built from `Host`/`X-Forwarded-Host` | 🔴 Host-header injection | Poisoned redirects/reset links | Medium | Use fixed canonical host |
| `Refresh: 0; url=<user-input>` | 🔴 | Redirect sink via non-standard header | Low–Medium | Validate |
| Redirect with `javascript:` scheme in Location | 🔵 | Browsers ignore for HTTP redirects; relevant for client-side redirects | Low | Validate schemes |

**Test bypass patterns (authorized):** `https://evil.example`, `//evil.example`, `/\evil.example`, `https:evil.example`, `https://example.com@evil.example`, `https://example.com.evil.example`, URL-encoded/double-encoded forms, `%0d%0a` header injection.

**Mitigation:** Avoid user-controlled redirects; use IDs mapped server-side; allowlist exact destinations; reject absolute URLs unless allowlisted; do not put secrets in redirect URLs.

---

## 16. Proxy / Forwarded Headers

| Header | Meaning |
|---|---|
| `Forwarded: for=203.0.113.9;proto=https;host=example.com` | Standardized (RFC 7239) proxy info |
| `X-Forwarded-For: 203.0.113.9, 198.51.100.7` | Chain of client/proxy IPs (leftmost = claimed client) |
| `X-Forwarded-Host: example.com` | Original `Host` requested |
| `X-Forwarded-Proto: https` | Original scheme |
| `X-Real-IP: 203.0.113.9` | Single client IP (nginx convention) |

> These are normally **request** headers added by proxies; they appear in **responses** when apps echo/debug them, or in error pages. During VAPT you test whether the application *trusts* client-supplied values and whether they are reflected.

### 16.1 Trusted-proxy architecture

```
Client ──► CDN/WAF ──► Load balancer ──► Reverse proxy ──► App
              ▲ overwrites/strips inbound forwarding headers
              └─ app trusts ONLY the known proxy IPs and takes the right-most untrusted hop
```
- The edge should **strip/overwrite** inbound `X-Forwarded-*`/`Forwarded`/`X-Real-IP`.
- The app should honor them **only** when the TCP peer is a configured trusted proxy.
- Determine client IP from the **right-most address not belonging to a trusted proxy**, not the leftmost.

### 16.2 Risk table

| Behavior | Classification | Risk | Mitigation |
|---|---|---|---|
| App uses leftmost `X-Forwarded-For` for IP allowlist/rate limit | 🔴 Vulnerable (bypass by spoofing `X-Forwarded-For: 127.0.0.1`) | Medium–High (if protecting admin/limits) | Trusted-proxy parsing |
| `X-Forwarded-Host` used to build absolute URLs/reset links | 🔴 Host-header poisoning | Medium–High | Static canonical host; validate against allowlist |
| `X-Forwarded-Host` reflected in cacheable response | 🔴 Cache poisoning | Medium–High | Unkey/strip header; no reflection |
| `X-Forwarded-Proto: https` trusted blindly | 🟡/🔵 | Wrong security decisions (e.g., skipping HTTPS redirect, insecure cookies) | Set only from trusted proxy |
| Logging raw XFF without sanitizing | 🟡 | Log injection / audit forgery | Sanitize and validate IP format |
| Internal IPs/hosts leaked in response headers | 🟡 | Recon | Strip at edge |
| Edge correctly overwrites headers | ✅ | Low | — |

**Test:** Send `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host: evil.example`, `X-Forwarded-Proto: http`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme`, and compare responses/behavior (redirects, access control, link generation, caching).

---

## 17. Rate-Limiting Headers

| Header | Meaning |
|---|---|
| `Retry-After` | Seconds (or HTTP-date) to wait; used with `429`, `503`, some `3xx` |
| `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` | IETF-draft standardized quota info (also `RateLimit-Policy`) |
| `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset` | De-facto (non-standard) equivalents; reset semantics vary (epoch vs seconds) |

| Observation | Classification | Interpretation |
|---|---|---|
| `429` + `Retry-After` + headers present, and limit actually enforced | ✅ | Good UX and enforcement |
| Headers present but limit **not enforced** (burst of requests all return 200) | 🔴 (missing rate limiting) | Headers are cosmetic |
| No headers but enforcement works (429/lockout/CAPTCHA) | ✅/🔵 | Absence of headers ≠ absence of limiting |
| Headers absent and no enforcement on login/OTP/reset | 🔴 / 🟡 | Brute-force/enumeration/abuse exposure |
| Limit keyed on spoofable header (`X-Forwarded-For`) | 🔴 | Bypass by rotating values |
| Per-IP only limit on distributed credential stuffing | 🔵 | Consider per-account/device limits |
| Headers disclose exact thresholds | 🔵 Informational | Helps attacker tune; trade-off with client usability |

> **Important:** The presence or absence of these headers **alone does not prove** that rate limiting is effective (or missing). Always test behavior empirically (e.g., controlled bursts within scope, header rotation, endpoint/method/case variants, API versions, concurrency).

**Mitigation:** Enforce server-side limits per account/IP/token/endpoint; return `429` + `Retry-After`; do not trust client-supplied IP headers; apply stricter limits on auth, OTP, reset, and expensive operations; monitor.

---

## 18. Authentication Headers

### 18.1 WWW-Authenticate (sent with `401 Unauthorized`)

| Challenge | Classification | Security considerations |
|---|---|---|
| `WWW-Authenticate: Basic realm="Restricted"` over **HTTPS** | 🔵 | Credentials base64-encoded (not encrypted); acceptable only over TLS; prefer stronger schemes; no logout/lockout semantics in browsers |
| `WWW-Authenticate: Basic realm="..."` over **HTTP** | 🔴 Vulnerable | Credentials sent in cleartext |
| `WWW-Authenticate: Digest realm="...", nonce="...", qop="auth", algorithm=MD5` | 🟡 Weak | MD5-based; legacy; prefer SHA-256 variants or modern auth |
| `WWW-Authenticate: Bearer realm="api"` | ✅ | Standard token challenge |
| `WWW-Authenticate: Bearer error="invalid_token", error_description="..."` | 🔵 | Useful, but descriptions should not leak internals (signature vs expiry vs issuer details) |
| `WWW-Authenticate: Negotiate` (Kerberos/SPNEGO) | 🔵 | Domain-internal; check NTLM fallback (`NTLM`) which is weaker and has relay risks |
| `WWW-Authenticate: NTLM` | 🟡 Weak/legacy | Relay/hash exposure concerns; disable where possible |
| Different `WWW-Authenticate` realms/messages for existing vs non-existing users | 🟡 | User enumeration |
| Realm reveals internal hostnames or product names | 🟡 | Information disclosure |

### 18.2 Proxy-Authenticate (sent with `407 Proxy Authentication Required`)

- Same schemes as above (`Basic`, `Digest`, `NTLM`, `Negotiate`) but for proxy credentials.
- Risks: Basic over cleartext proxy channel; open proxies; credential exposure in logs. **Mitigation:** TLS to proxy, strong scheme, restrict proxy to authenticated/internal clients.

### 18.3 Tests

- Does the endpoint return a proper `401` + challenge, or `200` with login HTML? (API consistency)
- Is HTTP Basic accepted over HTTP, or is there redirect to HTTPS?
- Are failed auth responses uniform across valid/invalid usernames?
- Can `Authorization` headers be cached? (`Cache-Control` on `401/200` responses)

---

## 19. Legacy / Deprecated Headers

| Header | Status | Should it be relied on? | Modern replacement |
|---|---|---|---|
| `X-XSS-Protection: 1; mode=block` | ⚪ Deprecated; removed from modern browsers (Chrome removed XSS Auditor; Firefox never implemented it). The legacy filter could introduce XS-Leaks/new bugs | **No** | CSP + contextual output encoding. If sent, `X-XSS-Protection: 0` is the recommended explicit value for legacy clients |
| `X-XSS-Protection: 0` | ✅ (legacy-safe) | n/a | Rely on CSP |
| `X-XSS-Protection: 1` (no mode=block) | ⚪🟡 | **No** | CSP |
| `X-Frame-Options: ALLOW-FROM uri` | ⚪ Obsolete | **No** (ignored in modern browsers) | CSP `frame-ancestors` |
| `X-Frame-Options: DENY/SAMEORIGIN` | Legacy but still honored | Secondary control | CSP `frame-ancestors` |
| `X-WebKit-CSP` | ⚪ Obsolete (old WebKit prefix) | **No** | `Content-Security-Policy` |
| `X-Content-Security-Policy` | ⚪ Obsolete (old Firefox/IE prefix) | **No** | `Content-Security-Policy` |
| `Feature-Policy` | ⚪ Deprecated | **No** | `Permissions-Policy` |
| `Public-Key-Pins` (HPKP) | ⚪ Removed; dangerous | **No** | Certificate Transparency, CAA, short-lived certs |
| `Expect-CT` | ⚪ Obsolete | **No** | Browser-enforced CT |
| `Pragma: no-cache` | ⚪ Legacy HTTP/1.0 | Not as primary | `Cache-Control` |
| `X-Download-Options: noopen` | ⚪ IE-only legacy | **No** | `Content-Disposition`, safe content handling |
| `X-Permitted-Cross-Domain-Policies` | Legacy plugin (Flash/Acrobat) | Optional (`none`) | N/A |
| `Set-Cookie2` | ⚪ Obsolete | **No** | `Set-Cookie` |
| `report-uri` (CSP) / `block-all-mixed-content` | ⚪ Deprecated directives | Not primary | `report-to`; `upgrade-insecure-requests` |

**Reporting guidance:** Presence of a deprecated header is **not a vulnerability** (Informational at most). Absence is also not a finding. Flag only where the app *relies* on a legacy header as its sole protection.

---

## 20. VAPT Testing Methodology

> Response-header testing must be combined with functional and exploitability testing. Headers are evidence; impact is proven by behavior.

| Step | Action | Details |
|---|---|---|
| **1 — Capture response** | Collect responses for diverse paths and states | Home, login, authenticated pages, API endpoints, static files, error pages (404/500), redirects, file downloads, `OPTIONS`/`HEAD`; both HTTP and HTTPS; both `GET` and `HEAD`. Record via Burp history. |
| **2 — Identify security headers** | Inventory what's present/missing per response type | Build a matrix: URL × header. Note inconsistencies (CSP on HTML only, cookies set by different tiers, headers added by CDN vs. origin). |
| **3 — Check values/directives** | Evaluate values against Sections 4–19 | HSTS max-age/includeSubDomains, CSP `unsafe-*`, XFO validity, Referrer-Policy strength, Permissions-Policy, duplicated/conflicting headers, syntax errors. |
| **4 — Test browser behavior** | Confirm enforcement in a real browser | Console CSP violations; framing PoC; mixed content; MIME sniffing test; HSTS behavior (`chrome://net-internals/#hsts` where available); cross-origin isolation (`window.crossOriginIsolated`). |
| **5 — Test CORS** | Manipulate `Origin` | Arbitrary, `null`, subdomain, regex bypass (`evilexample.com`), `http://` variants, preflight; check `ACAC` and `Vary: Origin`; build PoC against sensitive endpoints. |
| **6 — Test cookies** | Review every `Set-Cookie` | Flags, prefixes, scope, lifetime, entropy (separate test), fixation, logout invalidation, behavior over HTTP, behavior cross-site (SameSite). |
| **7 — Test caching** | Check sensitive responses | `Cache-Control`/`Pragma`/`Expires`; Back-button after logout; CDN `Age`/`X-Cache`; cache deception (`/profile/x.css`); `Vary`; poisoning via unkeyed headers. |
| **8 — Check information disclosure** | Look for banners and internals | `Server`, `X-Powered-By`, `X-AspNet*`, `Via`, `Server-Timing`, internal IPs/hosts, debug headers, request-ID formats. Map versions to CVEs *only* as separate findings when verified. |
| **9 — Validate exploitability** | Prove or downgrade | Can the weakness be abused under realistic conditions? Reflected-origin CORS → read victim data. Missing XFO → working clickjacking PoC on a sensitive action. Missing CSP → only meaningful alongside XSS. If not exploitable → report as hardening/defense-in-depth. |
| **10 — Document finding** | Use template in Section 24 | Include raw request/response evidence (redacted), affected URLs, conditions, CWE/OWASP. |
| **11 — Recommend mitigation** | Provide concrete config | Server/CDN config snippets and secure values (Section 25–26). |
| **12 — Retest** | Verify fix | Re-run same requests/PoC; test all response types and environments (staging/prod); confirm no regression (e.g., broken auth flows, CSP breakage). |

---

## 21. Burp Suite Checklist

### 21.1 Proxy → HTTP history
- [ ] Filter by **MIME type**, **status codes (200, 3xx, 4xx, 5xx)** and **in-scope** items only.
- [ ] Use search on response headers: `Set-Cookie`, `Access-Control-`, `Content-Security-Policy`, `Server`, `X-Powered-By`.
- [ ] Check **every distinct response class**: HTML, JSON API, static asset, redirect, file download, error page.
- [ ] Compare headers across **authenticated vs unauthenticated** responses.
- [ ] Note headers present on origin but stripped/changed by CDN/WAF (and vice versa).
- [ ] Look for **duplicated** security headers with conflicting values.
- [ ] Review redirects: `Location` targets, scheme, parameters reflected.

### 21.2 Repeater
- [ ] Modify `Origin` (arbitrary / `null` / lookalike) → observe ACAO/ACAC/Vary.
- [ ] Modify `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Original-URL` → observe reflection, redirects, access-control changes.
- [ ] Send `OPTIONS` preflights with `Access-Control-Request-*`.
- [ ] Try `HEAD`, `TRACE` (should be disabled), `OPTIONS` → compare `Allow` header.
- [ ] Alter `Accept`, `Accept-Encoding`, `Cookie` to see `Vary` behavior and caching.
- [ ] Test `?next=`, `?redirect=`, `?url=` parameters for `Location` manipulation.
- [ ] Remove/alter `Cookie` to see if `Set-Cookie` regenerates session (fixation checks).
- [ ] Try cache-buster parameters when testing cache behavior to avoid poisoning real users.

### 21.3 Inspector / Logger / Organizer
- [ ] Use **Inspector** to view parsed headers and cookies.
- [ ] Use **Logger** filters: e.g., response header regex for `Server:|X-Powered-By:`.
- [ ] Export unique header sets for reporting.
- [ ] Use **Comparer** to diff two responses (before/after header changes).

### 21.4 Burp Scanner (Professional/DAST)
- [ ] Review passive issues: missing/weak security headers, insecure cookies, CORS, cacheable HTTPS responses, information disclosure.
- [ ] **Manually validate** every scanner finding; scanners can't judge business context.
- [ ] Use active scans cautiously within scope; avoid cache-poisoning tests against production without approval.

### 21.5 What to inspect manually
| Item | What to check |
|---|---|
| `Set-Cookie` | Flags, prefixes, domain, path, lifetime, name/value patterns |
| `Content-Type` | Correct types and charset, user-controlled values |
| `Cache-Control` / `Pragma` / `Expires` | Sensitive pages cached? `public` on private data? |
| CSP | Bypass-prone sources, missing directives, report-only only |
| CORS | Reflection, null, credentials, regex flaws, `Vary` |
| `Location` | Open redirect, HTTP downgrade, sensitive query params |
| Debug/infra headers | Hostnames, internal IPs, versions, trace IDs |

---

## 22. curl Commands

> Use only against authorized targets. `example.com` is a placeholder.

```bash
# Basic header retrieval (HEAD)
curl -I https://example.com

# Ignore TLS validation (test environments only; note it hides certificate issues)
curl -k -I https://example.com

# GET request, show headers, discard body (preferred over HEAD)
curl -s -D - -o /dev/null https://example.com

# Follow redirects and show headers at each hop
curl -I -L https://example.com
curl -s -L -D - -o /dev/null https://example.com

# Show the redirect chain compactly
curl -s -L -o /dev/null -w "%{url_effective} -> %{http_code} (redirects: %{num_redirects})\n" http://example.com

# Check HTTP -> HTTPS redirect and HSTS
curl -s -D - -o /dev/null http://example.com
curl -s -D - -o /dev/null https://example.com | grep -i "strict-transport-security"

# Filter specific headers
curl -s -D - -o /dev/null https://example.com | grep -iE "^(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cache-control|set-cookie|server|x-powered-by)"

# With session cookie (placeholder only)
curl -s -D - -o /dev/null https://example.com/account -H "Cookie: session=<redacted>"

# Protocol versions
curl -s -D - -o /dev/null --http1.1 https://example.com
curl -s -D - -o /dev/null --http2 https://example.com
curl -s -D - -o /dev/null --http3 https://example.com    # if curl built with HTTP/3

# Open redirect checks
curl -s -D - -o /dev/null "https://example.com/login?next=https://evil.example"
curl -s -D - -o /dev/null "https://example.com/login?next=//evil.example"
curl -s -D - -o /dev/null "https://example.com/login?next=/\\evil.example"

# CORS checks
curl -s -D - -o /dev/null https://api.example.com/data -H "Origin: https://evil.example"
curl -s -D - -o /dev/null https://api.example.com/data -H "Origin: null"
curl -s -D - -o /dev/null https://api.example.com/data -H "Origin: https://trusted.example.evil.example"
curl -s -D - -o /dev/null -X OPTIONS https://api.example.com/data \
  -H "Origin: https://trusted.example" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: authorization,content-type"

# Forwarded-header trust checks
curl -s -D - -o /dev/null https://example.com/ -H "X-Forwarded-For: 127.0.0.1"
curl -s -D - https://example.com/ -H "X-Forwarded-Host: evil.example" | head -n 40

# Allowed methods
curl -s -D - -o /dev/null -X OPTIONS https://example.com/ | grep -i "^allow"
curl -s -D - -o /dev/null -X TRACE https://example.com/

# Cache behavior (add a cache-buster)
curl -s -D - -o /dev/null "https://example.com/profile?cb=$(date +%s)" -H "Cookie: session=<redacted>" | grep -iE "cache-control|pragma|expires|age|x-cache|vary"
```

---

## 23. Vulnerability Classification

> **Severity is contextual.** The "typical severity" below is a starting point; adjust for data sensitivity, authentication, user base, compensating controls, and demonstrated exploitability. Missing headers are **not automatically High/Critical**.

| Finding | Typical Severity | Exploitability | Example |
|---|---|---|---|
| Missing HSTS | Low (Informational on internal/non-sensitive) | Requires on-path attacker + first visit/expired policy | HTTPS site, no `Strict-Transport-Security` |
| Weak HSTS | Low / Informational | Same, shorter protection window | `max-age=300` |
| HSTS `max-age=0` | Low (Informational if intentional) | Policy cleared; same as missing | `max-age=0` on production |
| Missing CSP | Informational–Low (Medium if XSS confirmed and CSP would have blocked exploitation) | Not directly exploitable; reduces XSS impact | No CSP on app with stored XSS |
| Weak CSP | Low–Medium | Depends on XSS presence/bypass | `script-src 'self' 'unsafe-inline'` |
| Unsafe CSP | Medium (High with confirmed XSS + bypass) | Bypassable by design | `script-src 'self' data:` |
| Missing X-Content-Type-Options | Informational–Low | Needs sniffing-prone content (uploads) | User uploads served without `nosniff` |
| Missing X-Frame-Options / frame-ancestors | Low (Medium on sensitive one-click actions) | Clickjacking PoC needed | Framable "Delete account" page |
| Weak Referrer-Policy | Informational–Low | Needs sensitive data in URL + third-party sinks | `unsafe-url` with tokens in query |
| Weak Permissions-Policy | Informational | Requires injection/third-party embed + user prompt acceptance | `camera=*` |
| Insecure Cookie (general) | Low–Medium | Depends on missing attribute and threat model | Session cookie missing flags |
| Missing HttpOnly | Low–Medium (Medium if XSS exists) | XSS needed to steal cookie | Session cookie readable by JS |
| Missing Secure | Medium (on HTTPS apps) | On-path attacker; HTTP request needed | Session cookie sent over HTTP |
| Weak SameSite | Low–Medium | CSRF conditions required | `SameSite=None` on session without CSRF tokens |
| CORS wildcard | Informational–Low (Medium if private/intranet data) | Only non-credentialed reads | `ACAO: *` on public API |
| CORS origin reflection | Medium (High with credentials + sensitive data) | Attacker origin reads responses | Arbitrary `Origin` reflected |
| CORS with credentials | Medium–High | Cross-origin authenticated reads when origin trust flawed | `ACAO: <reflected>` + `ACAC: true` |
| Sensitive information caching | Low–High (data-dependent) | Shared device/proxy/CDN access needed | Bank statement cached by CDN |
| Server version disclosure | Informational–Low | Recon only | `Server: Apache/2.4.x` |
| X-Powered-By disclosure | Informational–Low | Recon only | `X-Powered-By: PHP/8.x` |
| Open redirect | Low–Medium (High in OAuth/SSO chains) | User interaction; phishing | `?next=https://evil.example` |
| Untrusted forwarding headers | Medium–High (if ACL/ rate-limit/ reset bypass proven) | Directly exploitable | `X-Forwarded-For: 127.0.0.1` bypasses admin ACL |

---

## 24. Finding Format

### 24.1 Reusable Template

```text
Title:
Description:
Affected URL:
Affected Parameter/Header:
Evidence:
Security Impact:
Risk:
CWE:
OWASP Mapping:
Severity:
Steps to Reproduce:
Expected Behavior:
Actual Behavior:
Mitigation:
Retest Recommendation:
```

### 24.2 CWE / OWASP mapping reference

> OWASP categories below use **OWASP Top 10:2021** (A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A07 Identification & Authentication Failures). If your engagement uses a newer edition, re-map accordingly. Also reference **OWASP ASVS** (V3/V9/V14) and **WSTG** (e.g., WSTG-CONF-07 HSTS, WSTG-CLNT-07 CORS, WSTG-SESS-02 Cookies, WSTG-CLNT-09 Clickjacking, WSTG-CLNT-04 Open Redirect).

| Finding | CWE | OWASP Top 10:2021 |
|---|---|---|
| Missing/Weak HSTS | CWE-319 (Cleartext Transmission) / CWE-523 | A02 / A05 |
| Missing/Weak CSP | CWE-693 (Protection Mechanism Failure) | A05 |
| Missing nosniff | CWE-693 / CWE-430 | A05 |
| Missing XFO / frame-ancestors | CWE-1021 (Improper Restriction of Rendered UI Layers) | A05 |
| Weak Referrer-Policy | CWE-200 / CWE-598 | A05 / A04 |
| Cookie missing Secure | CWE-614 | A05 / A02 |
| Cookie missing HttpOnly | CWE-1004 | A05 |
| Weak/missing SameSite | CWE-1275 | A01 / A05 |
| CORS misconfiguration | CWE-942 (Permissive Cross-domain Policy) | A05 / A01 |
| Sensitive info cached | CWE-524 / CWE-525 | A04 / A05 |
| Server/X-Powered-By disclosure | CWE-200 / CWE-497 | A05 |
| Open redirect | CWE-601 | A01 (commonly mapped; legacy A10:2013) |
| Untrusted forwarding headers | CWE-348 (Use of Less Trusted Source) / CWE-290 | A05 / A01 |
| Host header injection | CWE-20 / CWE-644 | A05 |
| HTTP request smuggling | CWE-444 | A05 |
| Session fixation | CWE-384 | A07 |

### 24.3 Worked example 1 — CORS origin reflection with credentials

```text
Title: Overly Permissive CORS Policy Allows Arbitrary Origin to Read Authenticated Responses
Description: The API reflects any value supplied in the Origin request header into
  Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true, without
  validating the origin against an allowlist.
Affected URL: https://api.example.com/v1/profile
Affected Parameter/Header: Origin (request) / Access-Control-Allow-Origin (response)
Evidence:
  Request:
    GET /v1/profile HTTP/2
    Host: api.example.com
    Origin: https://evil.example
    Cookie: session=<redacted>
  Response:
    HTTP/2 200 OK
    Access-Control-Allow-Origin: https://evil.example
    Access-Control-Allow-Credentials: true
    Content-Type: application/json
    {"email":"user@example.com", ...}
Security Impact: A malicious website visited by an authenticated user can read the
  user's profile data via cross-origin requests made from the victim's browser.
Risk: Confidentiality compromise of authenticated data. Exploitability depends on cookie
  SameSite behavior (cookie must be sent cross-site) and user interaction (visiting attacker page).
CWE: CWE-942
OWASP Mapping: A05:2021 Security Misconfiguration; A01:2021 Broken Access Control
Severity: Medium–High (contextual; confirmed data exposure)
Steps to Reproduce:
  1. Authenticate to https://app.example.com.
  2. Host a PoC page on a controlled origin issuing fetch(..., {credentials:'include'}).
  3. Visit the PoC page in the authenticated browser; observe response contents readable.
Expected Behavior: ACAO only returns exact trusted origins; others receive no ACAO.
Actual Behavior: Arbitrary origin is reflected with credentials allowed.
Mitigation: Server-side exact-match origin allowlist; never reflect unvalidated Origin;
  never allow "null"; add "Vary: Origin"; use SameSite=Lax/Strict cookies; require anti-CSRF.
Retest Recommendation: Replay with arbitrary/null/lookalike origins; confirm no ACAO is returned
  for non-allowlisted origins and PoC fails in the browser.
```

### 24.4 Worked example 2 — Missing HSTS (defense-in-depth)

```text
Title: HTTP Strict Transport Security (HSTS) Header Not Configured
Description: HTTPS responses do not include the Strict-Transport-Security header.
Affected URL: https://example.com/
Affected Parameter/Header: Strict-Transport-Security (absent)
Evidence: curl -s -D - -o /dev/null https://example.com  → no Strict-Transport-Security header.
Security Impact: Browsers are not instructed to enforce HTTPS, so an on-path attacker may
  downgrade or intercept a user's initial HTTP request (SSL stripping).
Risk: Low. Requires network-level attacker position; mitigated partly by existing HTTP→HTTPS redirect.
CWE: CWE-319
OWASP Mapping: A05:2021 Security Misconfiguration
Severity: Low
Steps to Reproduce: 1) Request the HTTPS site. 2) Inspect response headers. 3) Observe header absent.
Expected Behavior: Strict-Transport-Security: max-age=31536000; includeSubDomains
Actual Behavior: Header absent.
Mitigation: Add HSTS to all HTTPS responses; stage max-age; evaluate preload after subdomain audit.
Retest Recommendation: Confirm header on all HTTPS responses (incl. redirects/errors) and
  that HTTP redirects to HTTPS.
```

### 24.5 Condensed finding stubs (fill in the template above)

| Finding | Evidence to capture | Key "Actual vs Expected" |
|---|---|---|
| Missing/Weak CSP | Response headers of HTML pages; console behavior | Expected strict CSP; actual none / `unsafe-inline` |
| Clickjacking | Response headers + working iframe PoC screenshot | Expected `frame-ancestors`; actual framable |
| Insecure cookie | Raw `Set-Cookie` lines (redacted values) | Expected `Secure; HttpOnly; SameSite`; actual missing flags |
| Sensitive caching | Headers + evidence content retrievable after logout/from cache | Expected `no-store`; actual missing/`public` |
| Version disclosure | Header lines + (if any) verified CVE | Expected generic/no banner; actual detailed banner |
| Open redirect | Request with payload + `Location` + browser redirect | Expected allowlist; actual arbitrary destination |
| Forwarding header trust | Request with spoofed header + changed server behavior | Expected ignored from untrusted client; actual honored |

---

## 25. Mitigation Master Table

| Issue | Recommended Mitigation | Example Secure Configuration |
|---|---|---|
| Missing/Weak HSTS | Add HSTS on all HTTPS responses; HTTP→HTTPS redirect; gradual rollout; preload after audit | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| HSTS `max-age=0` | Use positive max-age on production | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| Missing/Weak CSP | Strict nonce/hash CSP; Report-Only rollout; remove `unsafe-*` | `Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'` |
| Unsafe CSP (`data:`, `*`, `unsafe-inline`) | Remove broad sources; refactor inline scripts | `script-src 'self'` (+ nonces) |
| Missing nosniff | Add header; set correct `Content-Type` | `X-Content-Type-Options: nosniff` |
| Clickjacking | CSP `frame-ancestors`; XFO fallback | `Content-Security-Policy: frame-ancestors 'none'` + `X-Frame-Options: DENY` |
| Weak Referrer-Policy | Stricter policy; keep secrets out of URLs | `Referrer-Policy: strict-origin-when-cross-origin` |
| Weak Permissions-Policy | Deny unused features; allowlist origins | `Permissions-Policy: camera=(), microphone=(), geolocation=()` |
| Insecure cookie flags | Set `Secure; HttpOnly; SameSite`; narrow scope; prefix | `Set-Cookie: __Host-session=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/` |
| Weak SameSite / CSRF | `Lax`/`Strict` + anti-CSRF tokens | `SameSite=Lax` + CSRF token |
| CORS wildcard on private data | Specific origins; auth checks | `Access-Control-Allow-Origin: https://trusted.example` + `Vary: Origin` |
| CORS reflection / null / regex flaws | Exact-match allowlist; reject `null` | Server-side allowlist (see below) |
| CORS with credentials | Only with a hardened trusted origin | `ACAO: https://trusted.example`, `ACAC: true`, `Vary: Origin` |
| Sensitive data caching | `no-store` (+ `private`); CDN bypass for authenticated content | `Cache-Control: no-store` |
| Cache deception/poisoning | Strict cache keys; ignore path suffixes; don't reflect unkeyed headers | CDN rule: cache only by explicit static paths |
| Server/X-Powered-By disclosure | Remove/minimize; patch software | `server_tokens off;` / `ServerTokens Prod` / `expose_php=Off` |
| Open redirect | Allowlist destinations; relative paths; signed state | Map `?next=` to known internal route IDs |
| Untrusted forwarding headers | Edge overwrites; trusted-proxy config; right-most-untrusted parsing | nginx `set_real_ip_from 10.0.0.0/8; real_ip_header X-Forwarded-For; real_ip_recursive on;` |
| Host header injection | Fixed canonical host; allowed-hosts list | App config `ALLOWED_HOSTS=['example.com']` |
| Rate limiting absent/bypassable | Server-side enforcement with `429` + `Retry-After` | Per-account + per-IP limits; not keyed on spoofable headers |
| HTTP Basic over HTTP / weak auth schemes | HTTPS only; modern auth | `WWW-Authenticate: Bearer realm="api"` |
| MIME/Content-Disposition issues | Correct types; `attachment` for user files; sandbox domain | `Content-Disposition: attachment; filename="file.pdf"` |
| Request smuggling | HTTP/2 end-to-end; patch proxies; reject ambiguous requests | Edge rejects CL+TE conflicts |
| Legacy header reliance | Replace with modern controls | CSP instead of `X-XSS-Protection`; `frame-ancestors` instead of `ALLOW-FROM` |

**Example server-side CORS allowlist (pseudocode):**
```python
ALLOWED = {"https://trusted.example", "https://app.example.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED:                      # exact string match only
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Vary"] = "Origin"
# else: do NOT send ACAO
```

---

## 26. Secure Baseline

### 26.1 Example response-header baseline (HTML application)

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{PER_RESPONSE_RANDOM}'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), fullscreen=(self)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

### 26.2 Secure cookie example

```http
Set-Cookie: session=<redacted>; Secure; HttpOnly; SameSite=Lax; Path=/
# Stronger, where possible:
Set-Cookie: __Host-session=<redacted>; Secure; HttpOnly; SameSite=Strict; Path=/
```

### 26.3 Logout response example

```http
HTTP/2 200 OK
Clear-Site-Data: "cache", "cookies", "storage"
Set-Cookie: __Host-session=; Max-Age=0; Secure; HttpOnly; SameSite=Lax; Path=/
Cache-Control: no-store
```

### 26.4 Adaptation notes (important)

| Setting | Why it must be adapted |
|---|---|
| **CSP** | Depends on scripts, CDNs, analytics, inline code, frameworks, and third-party widgets. Start in Report-Only. |
| **Permissions-Policy** | Allow only features the app needs (e.g., video-conferencing requires camera/mic for specific origins). |
| **Cookie SameSite** | `Strict` may break SSO/cross-site navigation; `None` is required for cross-site embeds/IdPs (with `Secure` + CSRF defense). |
| **HSTS includeSubDomains / preload** | Every subdomain (current and future) must support HTTPS before enabling. |
| **Caching** | `no-store` on everything harms performance; apply to sensitive/dynamic responses, use long `max-age` + `immutable` for fingerprinted static assets and `public` for truly public content. |
| **COOP/CORP/COEP** | May break OAuth popups, payment flows, third-party embeds; deploy only where required/compatible. |
| **X-Frame-Options / frame-ancestors** | Allow framing only for legitimate partners (use `frame-ancestors https://partner.example`). |
| **CORS** | Strictly per-API requirement; never one global wildcard policy for authenticated APIs. |

### 26.5 Static asset baseline

```http
Cache-Control: public, max-age=31536000, immutable
X-Content-Type-Options: nosniff
Cross-Origin-Resource-Policy: same-site
```

### 26.6 Sample server snippets

```nginx
# nginx (HTTPS server block)
server_tokens off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
proxy_hide_header X-Powered-By;
```
```apache
# Apache (mod_headers)
ServerTokens Prod
ServerSignature Off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
Header unset X-Powered-By
```

---

## 27. Quick VAPT Checklist

- [ ] **HSTS** — present on all HTTPS responses; `max-age` ≥ 1 year; `includeSubDomains` considered; not `max-age=0`; HTTP→HTTPS redirect works
- [ ] **CSP** — present and enforced; no `*`, `unsafe-inline`, `unsafe-eval`, `data:` in `script-src`; `object-src`, `base-uri`, `form-action`, `frame-ancestors` set
- [ ] **X-Content-Type-Options** — exactly `nosniff`
- [ ] **X-Frame-Options / frame-ancestors** — `DENY`/`SAMEORIGIN` or CSP equivalent; no `ALLOW-FROM`
- [ ] **Referrer-Policy** — `strict-origin-when-cross-origin` or stricter
- [ ] **Permissions-Policy** — unused features denied
- [ ] **COOP** — considered/set where cross-window isolation needed
- [ ] **CORP** — set on sensitive resources
- [ ] **COEP** — set only if cross-origin isolation is required
- [ ] **Cookies** — `Secure`, `HttpOnly`, `SameSite`, scope, lifetime, prefixes, fixation, logout
- [ ] **CORS** — no origin reflection, no `null`, no wildcard with sensitive data, allowlist, `Vary: Origin`
- [ ] **Cache-Control** — `no-store` on sensitive responses; no `public` on authenticated content; `Vary` correct
- [ ] **Server disclosure** — no unnecessary version/module banners
- [ ] **X-Powered-By** — removed (and `X-AspNet*`, `X-Generator`)
- [ ] **Redirects** — no open redirect; HTTPS targets; no secrets in `Location`
- [ ] **Forwarded headers** — client-supplied values not trusted; edge overwrites; Host validation
- [ ] **Rate limiting** — enforced behavior verified; `429` + `Retry-After`; not bypassable via spoofed headers
- [ ] **Authentication headers** — `WWW-Authenticate` challenge appropriate; no Basic over HTTP; no user enumeration
- [ ] **Content-Type** — accurate type + charset; no sniffing exposure; no HTML for JSON
- [ ] **Content-Disposition** — `attachment` for untrusted files; safe filenames
- [ ] **Legacy headers** — no reliance on `X-XSS-Protection`, `ALLOW-FROM`, `X-WebKit-CSP`, `Feature-Policy`, HPKP, Expect-CT

---

## 28. Important Accuracy Rules

1. A **missing security header is not automatically "vulnerable"**; it is usually a hardening/defense-in-depth gap.
2. Explain whether a header is **defense-in-depth** (CSP, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, HSTS) or **directly exploitable when misconfigured** (reflected-origin credentialed CORS, open redirect, trusted `X-Forwarded-*`, cacheable sensitive responses, insecure session cookies).
3. Distinguish a **configuration weakness** from a **confirmed vulnerability**; require a PoC or clear exploit path for higher severities.
4. Always consider **application context** (data sensitivity, authentication, user population) and **browser behavior** (SameSite defaults, CORS credential rules, third-party-cookie restrictions).
5. Do **not** recommend obsolete mechanisms as primary controls (`X-XSS-Protection`, `ALLOW-FROM`, HPKP, `Pragma`).
6. Clearly mark **deprecated headers** (⚪) and provide modern replacements.
7. Modern replacements: CSP replaces `X-XSS-Protection`/`X-WebKit-CSP`/`X-Content-Security-Policy`; `frame-ancestors` replaces `ALLOW-FROM`; `Permissions-Policy` replaces `Feature-Policy`; `Cache-Control` replaces `Pragma`/`Expires`; `report-to` replaces `report-uri`.
8. Never expose real credentials, tokens, cookies, or secrets; always **redact** in evidence.
9. Use `example.com`, `example.net`, `*.example`, `evil.example` and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) only.
10. Keep all examples safe and suitable for **authorized** VAPT only; obtain written authorization and respect scope/rules of engagement.
11. Provide **mitigation immediately** for each finding.
12. Use **technically correct terminology** (origin vs site, `no-cache` vs `no-store`, `HttpOnly` vs `Secure`, preload vs `includeSubDomains`).
13. For each header, evaluate in this order: **Purpose → Values → Secure → Weak → Vulnerable (if applicable) → Risk → Mitigation**.
14. Test **multiple value combinations**, not just one example.
15. Explain **why** each combination is secure, weak, vulnerable, or context-dependent.
16. **Do not confuse browser-enforced behavior with server-side security controls** — CORS, CSP, XFO, and cookie flags are enforced by compliant browsers; non-browser clients ignore them, and server-side authorization/validation is still required.
17. Combine response-header review with **functional and exploitability testing** before assigning severity.

---

*End of document.*
