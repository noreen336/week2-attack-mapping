

https://github.com/user-attachments/assets/09fe64d8-816f-4c2d-b197-130c3843218e

#  Passive Security & Compliance Audit Report
###  MITRE ATT&CK Reconnaissance Mapping — Individual Deliverable (Week 2)

**Project Name:** MITRE ATT&CK Mapping Module  
**Target Domain:** `safexsolutions.com`  
** Name:** Noreen Nasir  
**Group Association:** Group 33 (Individual Contribution)  
**Assessment Date:** July 18, 2026  
**Classification:** CONFIDENTIAL - FOR ACADEMIC EVALUATION PURPOSES ONLY  

---

##  1. Executive Summary
This repository contains the comprehensive technical audit module representing the individual Week 2 contribution submitted on behalf of Group 33. The primary objective of this exercise was to perform a completely passive, non-intrusive security analysis of `safexsolutions.com` and to contextually map the resulting intelligence against specific adversary techniques defined within the **MITRE ATT&CK Framework Matrix**.

###  Authorization & Constraints
* **Strict Passive OSINT Only:** No active scanning, fuzzing, automated vulnerability exploitation, or traffic-intercepting requests were performed against the target's corporate networks or infrastructure.
* **Data Sources:** All analytical inputs were harvested exclusively from public registries, global certificate transparency logs, distributed public DNS resolvers, and unauthenticated HTTP response data returned directly by the target's edge assets.

###  Summary of Perimeter Risk Profile
The assessment uncovered active configuration gaps that an external threat actor could systematically leverage during the early stages of a targeted attack lifecycle:
*  **High Severity (2):** Weak Outbound Email Authentication (SPF Softfail / Missing DMARC) & Missing Core Client-Side HTTP Security Headers (CSP & X-Frame-Options).
*  **Medium Severity (1):** Exposed Development/Staging Subdomain Footprint within public Transparency Logs.
*  **Low Severity (1):** Open WHOIS Metadata disclosure (adequately managed via a Registrar Privacy Proxy).
*  **Informational (1):** CDN Shielding Verification via Shodan (Origin IP successfully hidden).

---

##  2. MITRE ATT&CK Technique Mapping Table

| Reconnaissance Activity / Tool | MITRE ATT&CK Tactic | Technique ID & Specific Name | Real Observed Technical Evidence | Risk Severity | Blue Team Mitigation & Fix (M-ID) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WHOIS Metadata Lookup** | Reconnaissance | **T1596.002** Search Open Technical Databases: WHOIS | Registrar (`HOSTINGER operations, UAB`) and domain status flags are visible. Registrant contact metadata is obfuscated via privacy abuse-proxy service (`abuse-tracker@hostinger.com`). | **Low** | **M1037:** Maintain active privacy proxy services to block raw harvester scripts and target profiling. |
| **crt.sh Certificate Search** | Reconnaissance | **T1596.003** Search Open Technical Databases: Digital Certificates | Disclosed an active subdomain blueprint layout (`clinic.`, `healthcare.`, `sdc.`, `trust.`, `smoke.`, and `gpuhosting.safexsolutions.com`) issued within short temporal intervals. | **Medium** | **M1035:** Decommission unused staging points. Restrict staging visibility via internal VPN gateways or source IP restrictions[cite: 2]. |
| **Shodan Host Query** | Reconnaissance | **T1596.005** Search Open Technical Databases: Scan Databases | Hostname query returned zero raw results, verifying the origin server sits completely shielded behind a managed CDN platform (`Hostinger CDN / hcdn`)[cite: 2]. | **Info** | **No Action:** Maintain the current CDN layer layout. Ensure future test subdomains do not expose origin routing[cite: 2]. |
| **DNS TXT Record Query** | Reconnaissance | **T1590.002** Gather Victim Network Information: DNS Properties | Public query exposed an SPF record configured with a loose softfail qualifier (`~all`). No organizational DMARC (`_dmarc`) policy record exists[cite: 2]. | **High** | **M1049:** Restructure SPF mechanism to hardfail (`-all`). Deploy strict organizational DMARC records (`p=quarantine` or `p=reject`)[cite: 2]. |
| **curl HTTP Header Inspection** | Reconnaissance | **T1592.002** Gather Victim Host Information: Software | Response exposed explicit technology stacks via `X-Powered-By: HostingerWebsiteBuilder` and `Server: hcdn`. Lacks full script-constraining CSP and `X-Frame-Options`[cite: 2]. | **High** | **M1037:** Deploy missing header controls at the edge. Strip runtime software identifiers to mitigate platform-specific vulnerability targeting[cite: 2]. |

---

##  3. Deep-Dive Findings & Adversary Vector Analysis

### Find 1: Outbound Email Spoofing Vulnerability (SPF Softfail & Missing DMARC)
* **Observed String:** `v=spf1 include:_spf.mail.hostinger.com include:_spf.reach.hostinger.com ~all`[cite: 2]
* **Threat Matrix Impact:** Threat actors can execute **T1585.002 (Email Spoofing Infrastructure setup)**[cite: 2]. Because the domain uses a loose softfail mechanism (`~all`) and completely lacks a `_dmarc` policy, receiving mail servers are given no explicit mandate to discard or reject unauthorized mail streams impersonating `@safexsolutions.com`[cite: 2]. This facilitates high-success corporate phishing or Business Email Compromise (BEC) campaigns targeting staff and vendors[cite: 2].
* **Remediation Action:** Move to a strict hardfail mechanism (`-all`)[cite: 2]. Publish a foundational DMARC TXT record under `_dmarc.safexsolutions.com`[cite: 2]: 
  ```text
  v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@safexsolutions.com
# week2-attack-mapping
 Week 2 ATT&amp;CK mapping module
