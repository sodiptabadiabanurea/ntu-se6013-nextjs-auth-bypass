## Crafted flow (CVE-2025-29927), v14.2.24 - corrected

Client sends request with header:
  x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
  (the value must equal params.name - the middleware's internal name -
  repeated 5 times, colon-separated; a single occurrence is not enough)

  -> sandbox.ts:86-91 splits header on ':', counts entries equal to params.name
  -> count reaches MAX_RECURSION_DEPTH (5) -> depth >= 5 is true
  -> sandbox.ts:94-101 returns early with 'x-middleware-next': '1',
     the middleware body never executes
  -> route handler receives the request with no auth check having occurred
  -> protected content returned

## Negative control (v14.2.24)

Same request, header value = "middleware" (single occurrence, count = 1)
  -> depth (1) < MAX_RECURSION_DEPTH (5) -> condition false
  -> middleware executes normally -> auth check enforced

## Reviewer's independent lab observations (v14.2.24, NOT run by M3's runner)

| Header value | /lab/vulnerable/dashboard | /lab/vulnerable/api/records |
|---|---|---|
| `middleware` (count=1) | 307 (redirect, denied) | 401 (unauthorized) |
| `middleware:middleware:middleware:middleware:middleware` (count=5) | 200 + protected marker | 200 + protected marker |

These are the reviewer's own spot-check results, recorded here as the
condition M3's runner must reproduce - not results from M3's runner itself.

## Same request against v14.2.25 (patched)

Client sends request with the 5x-repeated header value, but supplies no
valid x-middleware-subrequest-id (the server's per-boot secret is not
disclosed to this request).
  -> filterInternalHeaders checks x-middleware-subrequest-id against the
     server's own secret -> mismatch (or missing)
  -> x-middleware-subrequest header is deleted
  -> sandbox.ts's check sees no valid header, regardless of repetition count
  -> Middleware runs normally -> auth check enforced

For the fixed CVE-2025-29927 request used in this lab, no valid
server-issued identifier is supplied, so 14.2.25 removes the forged
header and the bypass fails. This is narrower than a claim that the
identifier can never be exposed under any circumstance.

Note: this diagram describes the CVE-2025-29927 bypass path and its fix
only. It does not address CVE-2025-30218 (a separate, low-severity
id-leakage issue also present in 14.2.25), which was out of scope for
this lab and not tested here. See source-map.md for details.

## Deployment paths vs. shared-source contract

The shared-source contract (this repo's app code) defines:
- /lab/vulnerable/dashboard
- /lab/vulnerable/api/records

The current operator-gated preparation web additionally maps:
- /1 -> the original (vulnerable) app, with direct routes
  /1/dashboard and /1/api/records
- /2 -> the historical patched app, with direct routes
  /2/dashboard and /2/api/records

These are two separate environments, not a replacement of one by the
other; keep both documented. The browser gateway in front of the hosted
preparation web filters internal-use headers, so M3 must evaluate the
private target directly rather than through the public browser gateway,
which would strip the exact header this test depends on. Operator
authentication on the gateway and the target application's own session
are separate concerns and must not be conflated.

## M2 -> M3 handoff

**Exact version:** 14.2.24 (vulnerable baseline)

**Full lab paths to test (shared-source contract):**
- /lab/vulnerable/dashboard
- /lab/vulnerable/api/records

**Hosted preparation web mapping (if testing there instead):**
- /1/dashboard, /1/api/records -> vulnerable (14.2.24)
- /2/dashboard, /2/api/records -> patched (14.2.25)
- Test the private target directly, not through the public browser
  gateway, which filters the x-middleware-subrequest header.

**Working header value (positive case):**
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
(confirm the exact middleware name string - params.name - from M1's
middleware.ts/config before hardcoding it into the runner; "middleware"
above is a placeholder matching the generic case)

**Negative control (required):**
x-middleware-subrequest: middleware   (single occurrence)
Expected: 307 on /dashboard, 401 on /api/records, no protected marker -
this proves the scenario tests the 5-repetition condition specifically,
not just "any header present."

**Scenario definitions to add/update in the runner:**
- anonymous-cve-negative: single-occurrence header -> expect denial
- anonymous-cve-positive: 5x-repeated header -> expect marker present
