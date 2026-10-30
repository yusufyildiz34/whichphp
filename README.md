# whichphp

**Which PHP is inside this container image, and is it really fixed for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)? whichphp answers without running the image.**

> **Status: pre-release.** The first release is planned for November 4, 2026. Until then, this repository holds the design, the documentation and the test cases. The CLI and the public index are being built.

## What it does

- **Finds every PHP in an image.** That includes the CLI, PHP-FPM, Apache's `mod_php` (`libphp`), CGI, and embedded or static builds. It reads the image layers and never executes anything.
- **Gives a verdict for each CVE, with the evidence.** It understands distro backports, third-party builds and end-of-life branches. A verdict always says *why*: which binary, which package release, which data source.
- **Reads the image's PHP settings.** It reports the effective `php.ini` defaults, including `session.upload_progress.enabled`. Turning that setting off is the only mitigation for CVE-2026-115560, which is still unfixed.
- **Publishes a daily index of popular PHP images** (planned). For each tag and architecture it will show the PHP version, the verdict, when the tag was last rebuilt and the first digest that carried the fix.

## Which question are you asking?

| Your question | Short answer | Where to look |
|---|---|---|
| "`php -v` says 8.3.6. Am I patched?" | The version number alone can't tell you. Distros backport fixes without changing it. | [Why `php -v` lies](#why-php--v-lies), `whichphp image` |
| "Is the image tag I pull fixed yet?" | Floating tags were rebuilt within days. Pinned and end-of-life tags often never are. | `whichphp image <ref>`, the index (coming) |
| "Which PHP actually serves my site?" | Often not the one `php -v` shows. Images and hosts can carry several builds. | `whichphp image` lists every binary and SAPI |
| "I'm on PHP 8.1 or older." | There is no upstream fix. Treat it as vulnerable unless your vendor proves a backport. | [Verdicts](#verdicts) |
| "Is the CVE-2026-115560 mitigation on?" | In most images it isn't. Official images ship no `php.ini`, so the compiled default (on) applies. | `whichphp image` reports the effective value |
| "My scanner says the image is clean." | Package-based scanners can't see PHP compiled from source. | [Why your scanner says clean](#why-your-scanner-says-clean) |
| "Do I need to restart or redeploy?" | Yes. A running container keeps the old image until it is recreated. Save logs first. | Cluster mode (v0.2) |
| "My site is on shared hosting." | You can't scan it yourself. Ask your host the right questions. | [What to ask your host](docs/ask-your-host.md) · [Türkçe](docs/ask-your-host.tr.md) |
| "Was I compromised?" | whichphp can't tell you. A "fixed" verdict says nothing about what happened before. | [NCSC-NL PHP2Shell repository](https://github.com/NCSC-NL/php2shell) and your vendor's guidance |
| "Does a WAF protect me?" | Only partly, and only as a stopgap. Rules can miss variants. | [FAQ](#faq) |

## The fixes

| Branch | First fixed release (Oct 21, 2026) |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 (the branch reaches end of life on Dec 31, 2026) |
| 8.1 and older | No upstream fix |

- **Affected versions.** NVD lists CVE-2026-109618 as affecting PHP from 7.3.0 and CVE-2026-109619 from 5.4.0.
- **CVE-2026-115560 has no fix yet.** Until PHP's next regular release, the mitigation is `session.upload_progress.enabled = 0`, set server-wide.

## Why `php -v` lies

1. **Distros backport fixes without changing the version.** Ubuntu 24.04 ships PHP 8.3.6. Its security fixes show up in the package release (`8.3.6-0ubuntu0.24.04.N`), not in the version number. A checker that compares `8.3.6` with `8.3.36` gets it wrong.
2. **The CLI is not what serves your site.** `php -v` runs the command-line binary. Your site runs on PHP-FPM or Apache's `mod_php`, which can be a different build.
3. **Containers keep the image they started with.** A tag can be rebuilt with a fixed PHP while your running container still uses the old one.

whichphp reads the package database and the binaries in the image layers, and it shows which evidence each verdict rests on.

## Why your scanner says clean

The official `php` images compile PHP from source. No package manager knows about it, so package-based scanners don't see it.

- **Trivy, and tools built on it, don't detect it.** Trivy's maintainers closed a pull request for PHP binary detection and said compiled-binary detection belongs to Aqua's commercial scanner ([aquasecurity/trivy#6524](https://github.com/aquasecurity/trivy/pull/6524)).
- **Syft and Grype do.** Syft has a PHP interpreter cataloger ([source](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/php/interpreter_cataloger.go)), and Grype matches what it finds.

In our tests on four pre-fix official `php` images (six image and architecture combinations), Grype flagged both CVEs every time. Trivy flagged neither. whichphp builds on Syft and Grype rather than replacing them. It adds the backport logic, the settings and the explanation.

## Verdicts

whichphp gives one verdict per CVE.

| Verdict | Meaning |
|---|---|
| `FIXED` | The PHP version includes the upstream fix |
| `FIXED_BY_DISTRO_BACKPORT` | The version looks old, but the distro's package release includes the fix |
| `VULNERABLE` | The fix exists upstream, but this build doesn't have it |
| `VULNERABLE_EOL` | The branch or base OS is end-of-life and no fix is proven |
| `NEEDS_VENDOR_CONFIRMATION` | A third-party build whose fix status only the vendor can confirm |
| `UNKNOWN` | Not enough evidence; the output says what is missing |
| `DATA_STALE` | The vulnerability data is too old to trust |

**Exit codes:** `0` fixed, `1` action needed, `2` unknown. An `UNKNOWN` is an honest answer, not a failure, and whichphp never turns it into "safe."

## What a verdict does not prove

- **Runtime overrides are invisible.** Environment variables, mounted ConfigMaps or pool files can change settings after the image is built.
- **Distro data can lag.** A backport may exist before the vulnerability feed knows about it.
- **Private backports can't be recognized.** A source build patched by hand looks like the unpatched version.
- **"Fixed" says nothing about earlier compromise.**
- **CVE-2026-115560 stays open everywhere** until PHP's next regular release.

## What whichphp never does

- It never runs an image or sends traffic to any server.
- It contains no exploit code or payloads.
- It never says "not compromised."
- It doesn't fix anything automatically.

## FAQ

**A scanner tried to exploit my site and couldn't. Am I safe?**
No. A failed attempt shows that one technique didn't work under those conditions. Check the PHP build itself.

**My logs show PHP2Shell patterns. Was I compromised?**
Not necessarily. A match shows an *attempt*. Confirming a compromise needs more evidence. See the [NCSC-NL repository](https://github.com/NCSC-NL/php2shell) and your vendor's guidance.

**I'm about to recreate my containers. Anything to do first?**
Save the logs and anything you may want to examine. Recreating a container deletes its logs and writable layer, which a compromise check may need.

**Is a WAF enough?**
No. It can block known patterns while you patch, but rules miss variants. Patch, and turn upload progress off.

**The update broke my app. Should I go back to the old version?**
No. The old version is vulnerable. Known regressions in 8.4.27 and 8.5.12 are being fixed upstream. Check the php-src issue tracker for your symptom.

## Roadmap

| Stage | What ships |
|---|---|
| **Launch (Nov 4)** | `whichphp image <ref>`; the public index; this README; the host page in English and Turkish |
| **v0.2** | `whichphp cluster`: what each pod actually runs and what to redeploy; SARIF and OpenVEX output; a GitHub Action; per-tag "tell me when it's fixed" feeds |
| **Later** | Fixed-build data for third-party packagers (Sury, Remi, GetPageSpeed, TuxCare, Freexian, CloudLinux, cPanel); CycloneDX export; diff mode; base-image lineage |

## Related tools

- **[Syft](https://github.com/anchore/syft) and [Grype](https://github.com/anchore/grype):** SBOMs and vulnerability matching. whichphp builds on them.
- **[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell):** the status of vendor products and appliances.
- **[getastra/php2shell-triage](https://github.com/getastra/php2shell-triage) and [php2shell-doctor](https://github.com/andreysheva/php2shell-doctor):** checks for regular servers.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Verdict corrections need evidence, and new test cases are very welcome ([testdata/cases](testdata/cases/README.md)).

## License

[Apache License 2.0](LICENSE)
