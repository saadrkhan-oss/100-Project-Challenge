# Ethical Guidelines — Phishing Simulation

## Legal Framework

This tool is for **security awareness training only** and must be used within
the following legal constraints:

- **CFAA (US)**: Unauthorized access to computer systems is a crime.
- **GDPR (EU)**: Processing personal data requires explicit consent.
- **Computer Misuse Act (UK)**: Similar to CFAA.
- **Digital Millennium Copyright Act (US)**: Don't clone real websites.

## Rules

1. **Only test on your own accounts** — never target someone else.
2. **Get written permission** before testing an organization (use a signed
   "Rules of Engagement" document).
3. **Never clone real login pages** — use generic training pages (like this
   project's `login.html`).
4. **Never send real phishing emails** — use local templates and review them
   manually, or use a professional platform (GoPhish, KnowBe4) that handles
   consent and disclosure.
5. **Never harvest real credentials** — this project logs only simulated data.
6. **Never use found credentials** — even from a legitimate simulation, do not
   log into accounts.
7. **Report findings responsibly** — disclose vulnerabilities through proper
   channels (CVE, bug bounty, internal security team).
8. **Provide training** — any simulation must include follow-up awareness
   training for victims.
9. **Destroy captured data** — after the simulation, securely delete all
   harvested data and logs.
10. **Comply with all laws** — local, state, federal, and international.

## When in Doubt

- Ask your legal team.
- Ask your security team.
- **Don't do it.**

## Reporting Vulnerabilities

If you find a real vulnerability, report it via:
- The organization's security.txt (`/.well-known/security.txt`)
- Bug bounty platform (HackerOne, Bugcrowd)
- CISA (US), NCSC (UK), ENISA (EU)

## References

- GoPhish: https://getgophish.com/
- KnowBe4: https://www.knowbe4.com/
- OWASP Phishing: https://owasp.org/www-community/attacks/Phishing
