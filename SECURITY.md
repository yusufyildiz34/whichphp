# Security policy

## Vulnerabilities in whichphp

If you find a security problem in whichphp itself, for example a way for a crafted image to make whichphp run code or write outside its working directory, please report it privately through GitHub's **"Report a vulnerability"** button on this repository (Security → Advisories). Please don't open a public issue.

We aim to acknowledge reports within three days.

## A wrong verdict is not a security report

If whichphp calls an image fixed when it isn't, or the other way around, please open a public issue with the "Wrong verdict" template. Public verdict corrections help everyone who relies on the index.

## Vulnerabilities in PHP or in an image

whichphp doesn't handle these:
- **PHP itself:** report to the PHP project through its [security policy](https://github.com/php/php-src/security/policy).
- **A specific image:** report to that image's maintainers.

## What we won't accept

Exploit code, payloads or attack instructions, in any issue, pull request or report.
