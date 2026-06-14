# GDPR-Compliant AI System Design - Academic Assistant

> Conception and design of a **Responsible AI system compliant with GDPR** for academic assistance at ENSA Beni Mellal, covering legal analysis, ethical governance, risk mapping, and usage policy.

---

## Overview

This project addresses the challenge of integrating Artificial Intelligence into academic services while ensuring full compliance with **GDPR (General Data Protection Regulation)** and ethical AI principles.

The work covers four dimensions: legal compliance, ethical governance, risk management, and a usage policy framework — along with an application prototype.

---

## Project Structure

| Deliverable | Description |
|---|---|
| Legal Analysis | GDPR article-by-article compliance mapping |
| Governance Framework | AI supervision structure and accountability chain |
| Risk Mapping | Risk identification, scoring, and mitigation measures |
| Usage Policy | Access levels, authorized/prohibited uses |
| App Prototype | UI mockup of the AI assistant interface |

---

## Legal Analysis - GDPR Compliance

The system design is grounded in the **6 core GDPR principles (Art. 5)**:

| Principle | Implementation |
|---|---|
| Lawfulness | Documented legal basis under Art. 6.1.e |
| Data Minimization | Technical restriction on personal data input |
| Purpose Limitation | Exclusively academic use, enforced by access control |
| Storage Limitation | Auto-purge after 12 months, history capped at 2 years |
| Integrity & Security | Authentication, encryption, audit logging |
| Accountability | DPIA conducted, DPO designated, annual audit |

**User rights covered (Art. 13-22):** Access, Rectification, Erasure, Opposition, Protection against automated decisions.

**DPIA (Art. 35):** A Data Protection Impact Assessment was required and conducted, as the system combines automated processing with assisted decision-making.

---

## Ethical AI Governance

The governance framework defines a clear accountability chain:

```
University Direction
       |
       v
AI Supervision Committee
(DPO + Academic Lead + Tech Lead)
       |
       v
DPO -- GDPR compliance, DPIA, user rights
```

Key governance mechanisms:
- Quarterly supervision reviews
- Incident management procedures
- Human validation circuit (3 mandatory steps before any decision)
- Documented AI limitations

---

## Risk Mapping

10 risks identified, scored, and mitigated across the following categories:

- Data breach / unauthorized access
- Privacy violations
- Excessive AI dependency
- Excessive data retention
- Lack of transparency toward users
- Automated decision-making without human validation
- GDPR non-compliance (missing DPIA)

Mitigation measures include AES-256 encryption, automatic data filtering, expiring sessions, mandatory information notices, and a 3-step human validation circuit.

---

## Usage Policy

**Access levels defined:**

| Profile | Access Level |
|---|---|
| Students | Standard access |
| Academic staff | Extended access |
| Administrators | Supervisor access |
| Visitors / Third parties | No access |

**Authorized uses:** Academic text generation, document summarization, writing assistance, academic Q&A.

**Prohibited uses:** Personal data input, sensitive information, non-academic content, system bypass attempts.

---

## Application Prototype

The mockup covers 4 interface screens:
- Login page
- Main AI chat interface
- Request history
- Supervision dashboard

---

## Tech & Regulatory Stack

| Category | Reference |
|---|---|
| Privacy regulation | GDPR (EU) 2016/679 |
| AI ethics framework | EU Trustworthy AI Guidelines |
| Encryption standard | AES-256 |
| Risk methodology | CEPD criteria + severity/likelihood scoring |

---

## Context

- **Type:** Academic project (Project-Based Learning)
- **Program:** Artificial Intelligence & Cybersecurity (IACS), ENSA Beni Mellal
- **Supervised by:** M. Touil
- **Academic year:** 2025-2026

---

## Authors

Developed by a team of 2 students in Artificial Intelligence & Cybersecurity
ENSA Beni Mellal, Sultan Moulay Slimane University
