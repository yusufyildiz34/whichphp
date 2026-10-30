# What to ask your host about PHP2Shell

*[Türkçe](ask-your-host.tr.md)*

This page is for you if your site runs on shared or managed hosting and you have no shell access. You can't scan the server yourself, but you can ask questions that get a real answer instead of "we're protected."

## Background in one minute

- **CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell")** let an attacker run code on a server through PHP. PHP fixed them on October 21, 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.
- **CVE-2026-115560** has no fix yet. The mitigation is to turn off `session.upload_progress.enabled` on the server.
- **PHP 8.1 and older get no upstream fix.** Only a host or vendor backport can protect them.
- **Hosts often apply fixes without changing the version number,** so the version shown in your panel can look old even when it is fixed, or new when the running process is still old.

## Copy and send this

> Hello,
>
> I have questions about the PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619 (PHP2Shell, fixed upstream on October 21, 2026) and CVE-2026-115560, for my site **[your domain]**.
>
> 1. Which PHP version, and which exact build or package release, serves my site?
> 2. Is that build fixed for CVE-2026-109618 and CVE-2026-109619? If the version number looks older than 8.5.12, 8.4.27, 8.3.36 or 8.2.35, which backported package or build contains the fix?
> 3. When were the PHP processes serving my site (PHP-FPM, LiteSpeed or Apache) restarted after the update?
> 4. Is `session.upload_progress.enabled` turned off server-wide (in `php.ini` or as an admin setting) until PHP fixes CVE-2026-115560?
> 5. If my site runs PHP 8.1 or older, what do you recommend: an upgrade path, or a backported fix? If a backport, from which provider?
> 6. If your control panel uses its own PHP, is that updated too?
> 7. Did you see attempts against my site before the update? Will you keep the logs available if I need them?
>
> Thank you.

## Signs of a weak answer

- **"We're protected" or "we have a firewall,"** with no version or build. A firewall helps only while you patch.
- **Only a version number,** with no build or package release, when the number is older than the fixed releases.
- **"PHP 8.1 is fine."** It isn't, unless they name a backport.
- **No answer about restarts.** An installed update does nothing until the running processes restart.
- **Mitigation set only in your account's `.user.ini`.** Several hosts and PHP's own guidance say this is too late for CVE-2026-115560. It must be set server-wide.

## What you can check yourself

You can't prove a fix without the host, but these give you clues:

- **Your control panel's PHP version selector.** It shows the branch (8.3, 8.4…). Not proof, for the reasons above.
- **A temporary `phpinfo()` page.** Upload a file containing `<?php phpinfo();`, open it once, then **delete it right away**. Look for:
  - the PHP version and **Build Date**. A build date on or after October 21, 2026 is a good sign but not proof;
  - `session.upload_progress.enabled`, which should be **Off**;
  - the **Server API** line, which tells you whether PHP-FPM, LiteSpeed or Apache serves the site.
- **WordPress:** Tools → Site Health → Info → Server shows the PHP version the site uses.

## If you're worried about earlier compromise

- Ask the host to **keep the logs** before anything is reinstalled or migrated.
- Follow your host's guidance and the [NCSC-NL PHP2Shell repository](https://github.com/NCSC-NL/php2shell).
- A clean scan or a "fixed" version says nothing about what happened before the fix.

---

*Part of [whichphp](../README.md). Corrections are welcome; please include a source.*
