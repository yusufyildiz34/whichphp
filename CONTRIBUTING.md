# Contributing to whichphp

Thank you for helping. whichphp is only useful if its verdicts can be trusted, so contributions follow a few rules.

## Ground rules

- **Defensive only.** No exploit code, payloads, proof-of-concept requests or instructions for attacking systems, in code, issues, tests or docs.
- **Evidence for every verdict.** A change that makes whichphp call something fixed or vulnerable needs a source: a vendor advisory, a package changelog, a distro security tracker or a reproducible test case. Blog and forum posts are welcome as pointers, but they are never the only basis for `FIXED`.
- **`UNKNOWN` beats a guess.** If the evidence isn't there, the right answer is `UNKNOWN` with a note about what's missing.
- **Never execute what you scan.** whichphp reads image layers and metadata. It doesn't run images or binaries, and it doesn't send traffic to anyone's servers.

## Good first contributions

- **Test cases** from real reports (see [testdata/cases](testdata/cases/README.md)).
- **Fixed-build data** for a packager whose fixes aren't in machine-readable feeds (Sury, Remi, GetPageSpeed, TuxCare, Freexian, CloudLinux, cPanel). Include the source for each entry.
- **Images for the index.** Popular PHP images or tags that people pin.
- **Translations** of the [host page](docs/ask-your-host.md).

## Reporting a wrong verdict

Use the "Wrong verdict" issue template. Include the image reference and digest, the verdict whichphp gave, the verdict you expect, and your evidence.

## Naming third-party images

Before the public index or any post names a third-party image as vulnerable, its maintainers get at least 48–72 hours' notice. Please follow the same practice in issues and pull requests: describe the problem first, and name the image once the maintainers have been told.

## Pull requests

- Keep each pull request focused on one change.
- Add or update a test case when a verdict rule changes.
- Commits should explain *why*, not only *what*.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
