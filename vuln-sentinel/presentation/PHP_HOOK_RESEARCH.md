# PHP2Shell: research for the Blast Radius opening

Verified on October 23, 2026. These notes support a presentation hook, not a remediation guide. Use absolute dates if presenting after this week.

## The opening claim

**Attack attempts began four days before the patches.** AWS reported a PHP2Shell exploitation attempt in MadPot telemetry dated October 17, 2026. PHP's public emergency security release was October 21. Attempts are evidence of targeting; AWS did not establish that those attempts would have succeeded against real-world systems. [AWS first-party threat-intelligence report](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)

## What the PHP issue actually was

The October 21 release addressed CVE-2026-109618 and CVE-2026-109619, which can permit unauthenticated remote code execution in affected PHP web deployments. The first involves interrupted initialization after memory exhaustion; the second involves request state remaining after its underlying memory is freed. PHP highlighted Apache mod_php as the highest-risk configuration and described an exploit path reached before application code executes. These are runtime memory-safety flaws, not evidence that a PHP release was intentionally poisoned. [PHP security advisory](https://www.php.net/archive/2026.php)

For background on the particular version shown in the original slide: AWS lists PHP 8.3.0–8.3.35 as affected and 8.3.36 as the first fixed release on that branch for these two CVEs. Historical patch information should not be presented as a guarantee against every later PHP issue. [AWS PHP runtime bulletin](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)

## Why the attack opportunity exists

1. **The failure is below application login checks.** PHP parses requests before application code; the upstream advisory describes a demonstrated pre-application attack path in mod_php. An application's authentication alone therefore cannot be assumed to protect that path. [PHP advisory](https://www.php.net/archive/2026.php)
2. **A version must be found in the actual deployment.** Containers and applications can carry their own interpreter. Looking only at a command-line PHP version can miss the web runtime. This is part of the incident responder's inventory problem. [Datadog's independent reproduction and deployment guidance](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
3. **Public disclosure is not the start of exposure.** The October 17 telemetry is the verified example. AWS also reports later exploit activity following disclosure. [AWS report](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)

**Our product inference:** reusable infrastructure can spread the same technical exposure across deployments, while fragmented inventories make the response harder to coordinate. This motivates the hypothesis behind Blast Radius. We have not measured the response-time reduction or independently attributed attacker intent in this incident.

## Opening slide

**Headline:** Attack attempts began four days before the patches.

**Timeline:**

- **October 17:** exploitation attempt observed in AWS telemetry.
- **October 21:** PHP public emergency security release.
- **Responder's question:** Which of our deployments are exposed, and what can we safely change?

Footer: link the AWS report and PHP advisory. Keep CVE numbers and technical mechanics in speaker notes. Do not add percentages of the internet affected, breach counts, or losses without separate evidence.

## Transition into the implemented product

> Our current prototype covers npm and PyPI. This controlled Chalk scenario demonstrates the response workflow.

This transition matters: PHP runtime version inventory is different from Composer/Packagist package inventory. Loading Packagist alone would not discover PHP interpreters in running services or base images. The current prototype does not claim either capability.

## Correct the original slide

- Replace **“PHP 8.3.35 compromised”** with **“PHP 8.3.35 vulnerable to PHP2Shell”** if retaining the historical PHP example.
- Label that PHP screen as an illustrative target workflow if showing functionality outside the implemented prototype.
- Keep **“exploitation attempt observed”** distinct from **“successful breach confirmed.”**
- Do not say Blast Radius detected this PHP incident before disclosure. An advisory-driven prototype cannot claim that from this evidence.
- Do not promise that a local deployment gate isolates an already running PHP service. It can prevent a future pipeline step only when integrated and enforced.

## Source links

- [PHP official October 2026 announcements](https://www.php.net/archive/2026.php)
- [PHP advisory: CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory: CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [AWS first-party exploitation telemetry](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [AWS affected-runtime bulletin](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
- [Datadog independent reproduction and analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
