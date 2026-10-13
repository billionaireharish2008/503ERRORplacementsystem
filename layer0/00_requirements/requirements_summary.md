# Requirements summary (from the problem statement)

## Goal
A centralized, secure, policy-driven web application for the NFSU Placement Cell that keeps
course-wise student placement records and manages recruitment activity under the
Student Placement Guidelines for the **2026-27** placement session.

## Must maintain
Current student profiles; recruitment participation; offers; internship and full-time (FTE) details;
pre-placement offers (PPOs); package information; placement eligibility/status.

## Must do
- Automate policy checks, flag possible policy conflicts
- Reduce manual data-entry errors
- Prevent unauthorized changes
- Generate reliable placement statistics
- Build security and privacy in (system handles contact details and compensation)

## Programmes covered (as written in the problem statement)
1. M.Tech. Computer Science (M.Tech. CS)
2. M.Tech. Artificial Intelligence and Data Science (M.Tech. AIDS)
3. B.Tech.-M.Tech. Computer Science and Engineering (CS)
4. M.Sc. Computer Science (M.Sc. CS)
5. M.Sc. Digital Forensics and Information Security (M.Sc. DFIS)

> Naming check: the SCSDF brochure lists differently named programmes (e.g. "M.Tech. Cyber Security",
> "M.Sc. Cyber Security", "M.Sc. Digital Forensics and Information Security"). Confirm which names the
> system must use. See open question Q-12.

## 3.1 Student database - fields seen so far
| Field | Stated requirement |
|---|---|
| Placement ID | Unique identifier; reject duplicates |
| Student name | Full name as maintained by the institution |
| Mobile number | Registered contact number; access restricted by role |
| Email ID | Institutional or registered email address |
| ... | **rest of the table not seen - add here** |

Also stated: searchable, up-to-date; authorized create/view/update/archive; controlled import/export;
**preserve placement history rather than overwriting previous offer events.**

## NOT yet seen (add when available)
- Rest of 3.1 field table
- 3.2 Placement Policy Automation: offer-type restrictions; additional placement rules
- 3.3 Dashboard and Reports
- 4 Cybersecurity and Privacy requirements
- 5 Suggested System Workflow
- 6 Expected Deliverables  <- judges likely score against this; read first
