# Primary Source Ledger

| Source | URL | Supports |
|---|---|---|
| Official GitHub Security Advisory | github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw | Affected version ranges, fix versions, CVSS 9.1, official workaround |
| CVE record (NVD/cvelistv5) | nvd.nist.gov/vuln/detail/cve-2025-29927 | CWE-285 (Improper Authorization), publish date 21 Mar 2025 |
| Original researcher disclosure | zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware | Discovery process, header mechanism detail |
| Vercel postmortem | vercel.com/blog/postmortem-on-next-js-middleware-bypass | Vendor's own root-cause account, response timeline |
| Fastly technical write-up | fastly.com/blog/cve-2025-29927-authorization-bypass-in-next-js | Version-specific payload differences across major versions |
| GHSA-223j-4rm8-mrmf (CVE-2025-30218) | github.com/advisories/GHSA-223j-4rm8-mrmf | Qualifies our confidentiality claim about middlewareSubrequestId: documents id leakage to external hosts, affects 14.2.25, fixed in 14.2.26, CWE-200, CVSS v4 1.7. Not exploited in our lab. |
| Next.js source (v14.2.24) | github.com/vercel/next.js/blob/v14.2.24/packages/next/src/server/web/sandbox/sandbox.ts | Self-verified: exact vulnerable code, lines 84-104 |
| Next.js source (v14.2.25) | github.com/vercel/next.js/tree/v14.2.25/packages/next/src/server/lib | Self-verified: exact patched code (router-server.ts, server-ipc/utils.ts, context.ts) |
