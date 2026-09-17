# Security Policy

fastapi-fullauth handles authentication, so security reports get priority over all other work.

## Supported versions

The project is pre-1.0. Security fixes go into the latest minor release only; upgrade to receive them.

| Version | Supported |
|---------|-----------|
| Latest `0.x` minor release | Yes |
| Older releases | No |

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainer can see the report.

Please include:

- The affected version and configuration (adapter, token backend, blacklist/lockout/rate-limit backends, enabled routers)
- What an attacker can do, and what they need first (an account, a stolen token, network position)
- Steps or a minimal proof of concept to reproduce it
- Any fix you have in mind

## What happens next

1. The report is acknowledged, and you are told whether it is accepted as a vulnerability.
2. A fix is developed privately and released as a patch.
3. A GitHub security advisory is published with the release, crediting you unless you ask otherwise.

Please keep the details private until the advisory is published.

## Scope

In scope: anything in the `fastapi_fullauth` package, including its default configuration.

Out of scope: vulnerabilities in your application code, in dependencies (report those upstream), and weaknesses that require a configuration the documentation explicitly marks as unsafe for production. The [threat model](https://mdfarhankc.github.io/fastapi-fullauth/security/threat-model/) describes what the library defends against and what it leaves to your application.
