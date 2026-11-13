---
version: "1.0"
created: 2026-11-13
updated: 2026-11-13
---

# Scoped AI workspaces

**Version 1.0** · 2026-11-13

An inspectable slice of employee workspace engineering: read committed content,
select a finite approved subset, scan the exact bytes, and build a separate Git
history with an exact-tree check and an atomic reference transaction. The code
in `workspace_core.py` is selected unchanged from the working private builder;
`PROVENANCE.json` identifies each extracted symbol by hash. The demo collector
is new and intentionally limited to invented fixtures. [Claim map](evidence-map.json).

This complements the [AI OS architecture showcase](https://github.com/markyafi1991/personal-ai-operating-system).
It contains no vault records, live policy configuration or employee credentials.

```sh
python3 -B -m unittest discover -s tests -v
python3 -B demo.py
```

Requires Python 3.10+ and Git 2.29+. Tests create disposable synthetic repositories.
No package installation, network, token or actual vault is needed.

The source fixture contains an approved decision and an excluded invented record.
After committing, the demo changes the approved file and adds an untracked file.
Only the original committed approved decision enters the employee repository.
The source commit is recorded as metadata, never used as a Git parent.

The transaction verifies every resulting blob and its parent before moving the
branch and managed-history reference together. Tests inject a changed tree and
a failed compare-and-swap, then verify that the target branch did not move.
An unknown target history and symbolic references are refused. [Tests](tests/test_boundaries.py).

Separate repository content is one access boundary. Employee keys must be scoped
to their assigned repository; application connections require separate grants.
This demo provisions neither. A role prompt alone grants or restricts no tool.

Working proof: local Git selection and transaction behavior in the declared fixture.
Proposed or external: live employee access verification, automated refresh,
application grants, deployment operation and a complete v1 engagement.

See [report connection](REPORT.md), [publication review](PUBLICATION_REVIEW.md),
and [decisions and limits](DECISIONS.md). Release archive and verification receipts
identify the exact reviewed snapshot; CI results are separate evidence.
