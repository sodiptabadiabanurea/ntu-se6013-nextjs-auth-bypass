# SE6013 Software Security: Next.js authentication bypass

Group project workspace for studying CVE-2025-29927.

Verification-only branch: exercise the identity gate without student data. This change must not be merged.

Maintainer: [@sodiptabadiabanurea](https://github.com/sodiptabadiabanurea).

## Contributing

Members work in their own forks and open pull requests against `main`. Members do not receive write access to this repository. Only the maintainer reviews and merges contributions.

Every member PR must include their full name, matriculation number and checked public-disclosure acknowledgement. Missing or incomplete fields fail the required `Contributor identity` check and block normal merging. Completing the fields does not approve the code: the maintainer must also verify the identity and review the changes.

**Privacy notice:** this repository and its pull requests are public. Names and matriculation numbers submitted in PRs can be read, copied and indexed by others. Submit only your own details. Contact the maintainer before opening a PR if you do not agree to public disclosure; do not publish another person's identity.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the fork and PR steps.

## Repository controls

- `main` requires the identity status check and one approval from its code owner, @sodiptabadiabanurea.
- New code commits dismiss stale approvals; review conversations must be resolved.
- Force pushes and deletion of `main` are disabled.
- Members cannot push or merge into this repository. They push only to their own forks.
- The owner retains GitHub administrator override for owner-authored maintenance. This is not available to group members.

The identity check tests completed fields, basic identifier shape and disclosure consent. It does not query university records or prove a person's identity. The maintainer checks authenticity before approval.

## Current contents

This is a new collaboration scaffold, not the implemented security lab. No source code or history from the existing private project has been copied here. Existing work must be reviewed and explicitly cleared for public release before an import PR.

No lab is deployed, and no CVE experiment or remediation result is claimed by this repository setup.

## Local checks

```sh
python3 -m unittest discover -s tests -v
```

The identity workflow runs trusted code from the base repository only. It never checks out or executes contributor code while holding the status-writing token.
