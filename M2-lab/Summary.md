# M2 Summary - Root Cause of CVE-2025-29927

## One-line description
An authorization bypass in Next.js middleware: a request carrying the
x-middleware-subrequest header, with the middleware's own name repeated
5 times, is wrongly treated as an internal Next.js subrequest, causing
middleware (and any auth check inside it) to be skipped entirely.

## Root cause
Next.js uses x-middleware-subrequest to mark its own internal subrequests
and avoid infinite middleware loops. In v14.2.24, sandbox.ts (lines 84-104)
splits the header on ':' and counts occurrences of the middleware's own
name; once that count reaches MAX_RECURSION_DEPTH (5), middleware is
skipped with no check on where the request actually came from. Any
external client could construct that same header value and be treated as
trusted internal traffic.

## The fix (v14.2.25)
Next.js now generates a random, per-boot secret (middlewareSubrequestId).
Genuine internal subrequests are stamped with this secret via a second
header, x-middleware-subrequest-id. The filtering predicate in
filterInternalHeaders is conditional on identifier mismatch: it checks
whether the incoming x-middleware-subrequest-id matches the server's own
secret, and strips the original x-middleware-subrequest header only when
it does not. For the fixed CVE-2025-29927 request used in this lab, no
valid server-issued identifier is supplied, so the mismatch causes
14.2.25 to remove the forged subrequest header.

This fix is not an absolute confidentiality guarantee for the secret
itself - see the Scope and limits section below.

## Why this matters - the principles
- Authentication vs authorization: this bypasses the authorization
  check, not identity verification.
- Complete mediation: the crafted request opened a second path to the
  route handler that never passed through the auth checkpoint at all.
- Trusting client-supplied values: the vulnerable code treated a
  value the client fully controls - a header, repeated a specific number
  of times - as proof of trusted internal origin, with nothing to verify
  the claim.

## Scope and limits
- Only affects middleware-based authorization on self-hosted deployments
  (Vercel-hosted apps were automatically protected).
- A bypass of middleware does not itself defeat an independent backend
  authorization check (see M4's server-auth profile).
- This report covers the 14.2.24 to 14.2.25 pair for CVE-2025-29927 only;
  other affected major versions (11.x-13.x, 15.x) were not traced in this
  project.
- A separate, low-severity advisory (CVE-2025-30218) documents leakage of
  the middlewareSubrequestId itself and affects our patched baseline,
  14.2.25, fixed in 14.2.26. This was not tested in our lab. See
  [source map](Source-map.md) for the full qualification.

## Affected version ranges (official advisory)
See [source map](Source-map.md) for the complete table with exact bounds
(e.g. 14.x: >=14.0.0, <14.2.25) from GHSA-f82v-jwr5-mffw.

## Evidence classification

### Advisory facts (stated by vendor, not independently re-derived)
- Affected ranges and fix versions per major version
- CVSS 9.1 for CVE-2025-29927; CVSS v4 1.7 for CVE-2025-30218
- CVE-2025-30218 affects 14.2.25, fixed in 14.2.26

### Source-inspected conclusions (code we read and traced ourselves)
- sandbox.ts:84-104 (v14.2.24): the 5-repetition recursion-depth
  condition gating the middleware skip
- router-server.ts, server-ipc/utils.ts, context.ts (v14.2.25): the
  random per-boot secret and the filterInternalHeaders check that strips
  forged headers before they reach sandbox.ts
- Causal chain confirmed: filterInternalHeaders runs before sandbox.ts's
  header check, so a header failing the identifier-match predicate never
  survives to be read there
- For the fixed request evaluated here, no valid identifier is supplied,
  so the mismatch condition triggers and the forged header is removed
  before reaching the middleware-skip check. This is a statement about
  this specific request, not a general guarantee about the identifier's
  confidentiality in all cases - see the CVE-2025-30218 note above

### Reviewer measurements (independent spot-check; not run by M2 or M3)
- 14.2.24 baseline: single-name header -> 307 on /dashboard, 401 on
  /api/records; five-name header -> 200 with protected marker on both
  routes
- 14.2.25 target: five-name header -> refused (307/401)
- header-filter boundary: five-name header -> 400 with its own decision
  marker
- server-auth target: five-name header -> refused (307/401), with guard
  attribution in the response

## Sources
See [sources](sources.md) for the full ledger. Primary: official GitHub
advisory (GHSA-f82v-jwr5-mffw), original researcher disclosure, Vercel
postmortem, and GHSA-223j-4rm8-mrmf (CVE-2025-30218) for the
confidentiality limitation.

## Handoffs
- M3: exact version (14.2.24), full lab paths including the /1 and /2
  deployment mapping, working 5x-repeated header value, the required
  negative control (single occurrence), and the requirement to test the
  private target directly rather than through the browser gateway - see
  [request flow](Request%20flow.md).
- M4: exact file/line references for the patch mechanism, for explaining
  the header-filter and server-auth defences - see [source map](Source-map.md).
- M5: claim list - advisory facts vs. source-inspected conclusions vs.
  reviewer measurements (see Evidence classification above).
