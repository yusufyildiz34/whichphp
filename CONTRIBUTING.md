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

Before the public index or any post names a third-party image as vulnerable, we tell its maintainers. Please do the same in issues and pull requests: describe the problem first, and name the image once the maintainers have been told.

## Development and tests

whichphp needs Go 1.24 or later. Before you open a pull request, run:

```sh
gofmt -l .        # prints nothing when the code is formatted
go vet ./...
go test ./...     # CI adds -race, which on Linux and Windows needs cgo and a C compiler
```

On every pull request, CI also runs staticcheck, govulncheck, CodeQL, actionlint, shellcheck, zizmor and a short fuzzing pass over the parsers of untrusted input (Syft and Grype JSON, image references, registry headers, version strings, `php.ini` files and Kubernetes pod lists). Please get them all green. To fuzz a parser locally, for example: `go test ./internal/registry -run='^$' -fuzz=FuzzParseRef -fuzztime=1m`.

**Test policy:**

- New functionality in the Go code comes with tests in the Go test suite, and a bug fix comes with a test that fails without the fix.
- A change to a verdict rule also adds or updates a test case (see [testdata/cases](testdata/cases/README.md)).
- New code that parses data from images, SBOMs, Grype, registries or clusters gets a fuzz target, listed in the fuzz job in `.github/workflows/checks.yml`.

## Pull requests

- Keep each pull request focused on one change.
- Commits should explain *why*, not only *what*.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
