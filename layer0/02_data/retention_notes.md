# Data retention and handling notes (draft)
Classes: **public / internal / confidential personal / restricted placement-compensation**
(see `data_classification.csv`).

## Principles
- Collect only what is needed; hide phone/email from roles that do not need them.
- Offers are **never overwritten**; corrections create a new history entry with actor and reason.
- "Archive" means hidden from normal lists but retained; "delete" needs explicit approval.
- Development and demo use **synthetic or anonymised data only**. Database dumps and test exports are treated as real data.
- Exports exclude phone/email by default and are logged.

## Decisions the institution must make (not guessed here)
1. Retention period per class (student, offers, attendance, audit logs).
2. When a graduated batch is archived and who may still view it.
3. How duplicate imports and corrections are handled (reject vs merge-with-approval).
4. Backup retention and who can restore.
