---
version: "1.0"
created: 2026-11-13
updated: 2026-11-13
---

# Decisions and limits

**Version 1.0** · 2026-11-13

1. Select production transaction primitives, keep the collector synthetic. This
   makes the sensitive publication seam inspectable without shipping live export
   policy, repository grants or operational inventories. The fixture collector is
   not a general safe exporter: do not aim it at an actual vault.
2. Read immutable Git objects instead of rereading the working folder after
   review. Test the difference with committed, edited and untracked sentinels.
3. Start with a parentless commit. Copying a private repository and deleting
   files would retain its reachable history. The fixture creates its destination
   from checked bytes and never imports source parents.
4. Check the resulting tree before moving references. A successful command exit
   is insufficient evidence for byte identity. Inject a mismatched tree and a
   failed reference transaction to exercise the failure path.
5. Keep credentials and employee commissioning separate from repository content.
   This code does not audit account-wide applications or establish live access.

Secret signatures catch known formats; they cannot prove the absence of all
sensitive text. Public selection requires human semantic review in addition to
the documented mechanical checks. No private records were used as fixtures.

References: `workspace_core.py`, `demo.py`, `tests/test_boundaries.py`, and the
exact-source symbol hashes in `PROVENANCE.json`. These are implementation claims,
not borrowed frameworks or claims about a currently deployed employee.
