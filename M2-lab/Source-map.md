# Source Map - CVE-2025-29927

## Vulnerable (v14.2.24) - full middleware-skip condition

**File:** packages/next/src/server/web/sandbox/sandbox.ts, lines 84-104
(https://github.com/vercel/next.js/blob/v14.2.24/packages/next/src/server/web/sandbox/sandbox.ts#L84-L104)

```js
const subreq = params.request.headers[`x-middleware-subrequest`]
const subrequests = typeof subreq === 'string' ? subreq.split(':') : []
const MAX_RECURSION_DEPTH = 5
const depth = subrequests.reduce(
  (acc, curr) => (curr === params.name ? acc + 1 : acc),
  0
)
if (depth >= MAX_RECURSION_DEPTH) {
  return {
    waitUntil: Promise.resolve(),
    response: new runtime.context.Response(null, {
      headers: { 'x-middleware-next': '1' },
    }),
  }
}
```

**Full condition:** the x-middleware-subrequest header value is split on
':'. For each segment that equals params.name (the middleware's own
internal name), a counter increments. Middleware is skipped only once
that counter reaches MAX_RECURSION_DEPTH, which is 5. A single occurrence
of the name does NOT trigger the skip - it requires five repeated
occurrences, colon-separated. MAX_RECURSION_DEPTH = 5 is hardcoded in the
v14.2.24 source itself, so this applies directly to our 14.2.24 baseline,
not only to later major versions.

**File:** packages/next/src/server/web/sandbox/context.ts, lines 360-372
Where Next.js sets this header on its own legitimate internal subrequests
- the mechanism the bug abuses.

**Root problem:** any request carrying this header with the name repeated
5+ times, from anyone, was treated as proof of trusted internal origin.
There was no secret or check tying the header to an actual internal
request.

## Patched (v14.2.25)

**File:** packages/next/src/server/lib/router-server.ts, ~line 149-155
On server startup, generates a random 8-byte secret using
crypto.getRandomValues and stores it process-wide:
```js
const middlewareSubrequestId = Buffer.from(randomBytes).toString('hex')
;(globalThis as any)[Symbol.for('@next/middleware-subrequest-id')] =
  middlewareSubrequestId
```

**File:** packages/next/src/server/web/sandbox/context.ts, ~line 368-371
When Next.js makes a genuine internal subrequest, it now also stamps it
with x-middleware-subrequest-id, set to the server's own secret.

**File:** packages/next/src/server/lib/server-ipc/utils.ts, lines 57-72
filterInternalHeaders now checks whether the incoming
x-middleware-subrequest-id matches the server's own secret:
```js
if (header === 'x-middleware-subrequest' &&
  headers['x-middleware-subrequest-id'] !==
    (globalThis as any)[Symbol.for('@next/middleware-subrequest-id')]
) {
  delete headers['x-middleware-subrequest']
}
```
If it doesn't match (or is absent, as for any external attacker), the
original header is deleted before sandbox.ts's check ever reads it.

**What changed:** the fix adds a random per-boot secret and a filtering predicate in
filterInternalHeaders (server-ipc/utils.ts, lines 64-69 in v14.2.25) that
is conditional on identifier mismatch: it strips the original
x-middleware-subrequest header specifically when the incoming
x-middleware-subrequest-id does not match the server's secret. For the
fixed CVE-2025-29927 request evaluated in this lab, no valid identifier
is supplied, so the mismatch condition is met and the forged header is
removed before sandbox.ts's check ever reads it.

**Causal chain confirmed:** filterInternalHeaders (server-ipc/utils.ts)
runs on the request before it reaches the sandbox's header check, so a
forged header never survives to be read in the patched version.

## Limitation on the patched mechanism (reviewer-flagged)

The statement above that the random middlewareSubrequestId secret is
unforgeable should not be read as an absolute confidentiality guarantee.

A separate advisory, CVE-2025-30218 / GHSA-223j-4rm8-mrmf ("Next.js may
leak x-middleware-subrequest-id to external hosts"), documents that the
id itself can leak to external hosts under certain conditions. This is
classed as CWE-200 (exposure of sensitive information), rated low
severity (CVSS v4 1.7), and - critically for our project - lists 14.2.25
(our patched baseline) as affected, with 14.2.26 as the first fixed
version. It was discovered by Vercel itself while remediating
CVE-2025-29927, and independently confirmed by two external researchers
(Jinseo Kim and RyotaK, GMO Flatt Security).

**What this means for our comparison:** our 14.2.24 vs 14.2.25 pair
remains the correct historical comparison for CVE-2025-29927 specifically
(the authorization bypass), and 14.2.25 correctly closes that bypass. But
14.2.25 is not fully "secret-safe" for the id mechanism itself - a
narrower, separate leak exists in that same version. We did not exploit
or test CVE-2025-30218 in this lab; it is documented here only to avoid
overstating the confidentiality of the patched mechanism.

Reference: https://github.com/advisories/GHSA-223j-4rm8-mrmf

## Affected version ranges (official advisory GHSA-f82v-jwr5-mffw)

| Major | Affected range | First fixed version |
|---|---|---|
| 11.x | >=11.1.4 | No fix - workaround only |
| 12.x | >=12.0.0, <12.3.5 | 12.3.5 |
| 13.x | >=13.0.0, <13.5.9 | 13.5.9 |
| 14.x | >=14.0.0, <14.2.25 | 14.2.25 |
| 15.x | >=15.0.0, <15.2.3 | 15.2.3 |

The fixed version itself is excluded from the affected range: for 14.x,
">=14.0.0, <14.2.25" means 14.2.25 is NOT vulnerable to CVE-2025-29927.
Our baseline, 14.2.24, falls inside the affected range; our patched
comparison, 14.2.25, is the first version outside it (for this CVE only -
see the limitation above regarding CVE-2025-30218).
