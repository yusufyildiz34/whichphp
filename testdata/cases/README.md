# Test cases

Every verdict rule in whichphp should have a test case, and every case should come from something that happened: a bug report, a wrong verdict from another tool, or a real image. CI fails if a code change flips an expected verdict.

Today the cases run as Go tests on synthetic SBOMs, in `internal/verdict`, `internal/phpini` and `internal/phpver`. Each will also get a small directory here with a synthetic image layout (package database entries, version strings in placeholder binaries, ini files) and an `expected.json`. No real PHP binaries and no exploit material are stored here.

## Planned cases

| ID | Scenario | Evidence in the image | Expected verdict | Source |
|---|---|---|---|---|
| `official-prefix` | Official image, source build before the fix | `php` 8.4.26, no package database entry | `VULNERABLE` | Control images in our experiment |
| `official-fixed` | Official image after the fix | `php` 8.4.27 | `FIXED` | Same |
| `ubuntu-backport` | Distro build with a backported fix and an old version number | `php8.3-cli` `8.3.6-0ubuntu0.24.04.N` (fixed release) | `FIXED_BY_DISTRO_BACKPORT` | [openai/php2shell-checker#17](https://github.com/openai/php2shell-checker/issues/17), [MakFly/php2shell-check#2](https://github.com/MakFly/php2shell-check/issues/2) |
| `sury-prefix` | Third-party repo build that sorts above the distro's fixed release but is still upstream 8.3.35 | `8.3.35-…+deb.sury.org+1` | `VULNERABLE` | [aquasecurity/trivy discussion #11480](https://github.com/aquasecurity/trivy/discussions/11480) |
| `eol-branch` | End-of-life PHP branch built from source | `php` 8.1.34 | `VULNERABLE_EOL` | NVD ranges; experiment |
| `eol-os` | Distro PHP on an end-of-life distro release that its feed no longer tracks | PHP 7.3 package on Debian 10 | `VULNERABLE_EOL`, never "fixed per feed" | Experiment (analyzer bug found and fixed on Oct 30) |
| `packaging-suffix` | Upstream build with a packager's revision suffix | `8.2.29-2` | Parse as 8.2.29 → `VULNERABLE` | Experiment |
| `php-group-string` | Version text that isn't a version | Banner text "The PHP Group" | No version parsed; never `FIXED` from it | [openai/php2shell-checker#4](https://github.com/openai/php2shell-checker/issues/4) |
| `prerelease` | Development and release-candidate builds | `8.4.26-dev`; `8.4.27RC1` | `VULNERABLE` for 8.4.26-dev; `UNKNOWN` for the RC (fix inclusion not proven) | [openai/php2shell-checker#23](https://github.com/openai/php2shell-checker/issues/23) |
| `distro-dev-suffix` | A distro suffix that contains "dev" but isn't a prerelease | `8.4.27-1.devuan1` | `FIXED` | Same |
| `multi-sapi` | Several binaries in one image with different versions | CLI 8.4.27, FPM 8.4.26 | Per-binary verdicts; overall "action needed" | [MakFly/php2shell-check#1](https://github.com/MakFly/php2shell-check/issues/1) (binaries that can't be executed were misjudged) |
| `upload-progress-default` | Official image with no `php.ini` | No ini files | `session.upload_progress.enabled` = on (compiled default) | [docker-library/php#1690](https://github.com/docker-library/php/issues/1690) |
| `upload-progress-fpm-pool` | Mitigation set only in an FPM pool | `php_admin_flag[session.upload_progress.enabled] = off` in a pool file | Off for FPM, on for CLI | Experiment |
| `arch-mismatch` | Same tag, different PHP per architecture | amd64 8.2.35, arm64 8.2.34 | Separate verdicts, with an architecture warning | [docker-library/php#1704](https://github.com/docker-library/php/issues/1704) |

## Adding a case

Open an issue with the "Wrong verdict" template or send a pull request. Include:
- where the case comes from (a link);
- the evidence an image would contain (package names, version strings, ini lines);
- the verdict you expect, and why.

Please don't include exploit requests, payloads or real customer data.
