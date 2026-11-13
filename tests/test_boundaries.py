import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import demo
import workspace_core as core


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source, self.target, self.revision = demo.fixture(Path(self.temp.name))
        self.collection = demo.collect_synthetic(self.source, self.revision)

    def test_only_committed_allowlisted_bytes(self):
        self.assertEqual(self.collection["files"], [("approved/decision.md", b"Synthetic decision: test before release.\n")])

    def test_fresh_history_and_repeat(self):
        result = core._commit_collected(self.target, self.collection)
        self.assertEqual(len(demo.git(self.target, "rev-list", "--parents", "-n", "1", result["commit"]).split()), 1)
        self.assertFalse(core._commit_collected(self.target, self.collection)["committed"])
        self.assertNotEqual(result["commit"], self.revision)

    def test_second_changed_publish_preserves_checked_parent(self):
        first = core._commit_collected(self.target, self.collection)
        (self.source / "approved/decision.md").write_text("Synthetic updated decision.\n")
        demo.git(self.source,"add","approved/decision.md")
        demo.git(self.source,"commit","-qm","Synthetic source update")
        changed=demo.collect_synthetic(self.source,demo.git(self.source,"rev-parse","HEAD"))
        second=core._commit_collected(self.target,changed)
        self.assertTrue(second["committed"])
        parents=demo.git(self.target,"rev-list","--parents","-n","1",second["commit"]).split()[1:]
        self.assertEqual(parents,[first["commit"]])
        self.assertEqual(core.ref_value(self.target,core.PUBLISHED_REF),second["commit"])
        self.assertEqual(demo.git(self.target,"show","main:approved/decision.md"),"Synthetic updated decision.")

    def test_unknown_branch_history_refused(self):
        result = core._commit_collected(self.target, self.collection)
        demo.git(self.target, "update-ref", "-d", core.PUBLISHED_REF)
        with self.assertRaisesRegex(core.BuildError, "history is no longer known"):
            core._commit_collected(self.target, self.collection)
        self.assertEqual(demo.git(self.target, "rev-parse", "main"), result["commit"])

    def test_duplicate_paths_refused(self):
        self.collection["entries"].append(self.collection["entries"][0])
        with self.assertRaisesRegex(core.BuildError, "duplicate paths"):
            core._commit_collected(self.target, self.collection)
        self.assertIsNone(core.ref_value(self.target, "refs/heads/main"))

    def test_tree_tampering_prevents_branch_move(self):
        real = core.read_tree
        def changed(repo, commit):
            tree = real(repo, commit)
            tree["unexpected.txt"] = ("100644", "blob", "0" * 40)
            return tree
        with mock.patch.object(core, "read_tree", changed):
            with self.assertRaisesRegex(core.BuildError, "does not match"):
                core._commit_collected(self.target, self.collection)
        self.assertIsNone(core.ref_value(self.target, "refs/heads/main"))

    def test_compare_and_swap_failure_keeps_refs_unmoved(self):
        real = core.git_repo
        def fail(repo, *args, **kwargs):
            if args[:2] == ("update-ref", "--no-deref"):
                return subprocess.CompletedProcess(args, 1, b"", b"injected race")
            return real(repo, *args, **kwargs)
        with mock.patch.object(core, "git_repo", fail):
            with self.assertRaisesRegex(core.BuildError, "branch moved"):
                core._commit_collected(self.target, self.collection)
        self.assertIsNone(core.ref_value(self.target, "refs/heads/main"))
        self.assertIsNone(core.ref_value(self.target, core.PUBLISHED_REF))

    def test_committed_symlink_refused(self):
        (self.source / "approved/link.md").symlink_to("../excluded/record.md")
        demo.git(self.source, "add", "approved/link.md")
        demo.git(self.source, "commit", "-qm", "Synthetic symlink negative")
        with self.assertRaisesRegex(ValueError, "nonregular"):
            demo.collect_synthetic(self.source, demo.git(self.source, "rev-parse", "HEAD"))

    def test_secret_pattern_refused_without_value_in_error(self):
        marker = "gh" + "p_" + "A" * 40
        (self.source / "approved/token.md").write_text(marker)
        demo.git(self.source, "add", "approved/token.md")
        demo.git(self.source, "commit", "-qm", "Synthetic secret negative")
        with self.assertRaisesRegex(ValueError, "Secret-like bytes") as error:
            demo.collect_synthetic(self.source, demo.git(self.source, "rev-parse", "HEAD"))
        self.assertNotIn(marker, str(error.exception))

    def test_normalized_deny_prefix(self):
        self.assertTrue(core.is_under_folded("PRIVATE/record.md", ["private/"]))
        self.assertTrue(core.is_under_folded("cafe\u0301/record.md", ["caf\u00e9/"]))

    def test_symbolic_target_reference_refused(self):
        demo.git(self.target, "symbolic-ref", "refs/heads/main", "refs/heads/other")
        with self.assertRaisesRegex(core.BuildError, "symbolic reference"):
            core._commit_collected(self.target, self.collection)

    def test_symbolic_managed_reference_refused(self):
        demo.git(self.target,"symbolic-ref",core.PUBLISHED_REF,"refs/heads/other")
        with self.assertRaisesRegex(core.BuildError,"symbolic reference"):
            core._commit_collected(self.target,self.collection)

    def test_secret_filename_refused(self):
        (self.source/"approved/.env").write_text("SYNTHETIC=only\n")
        demo.git(self.source,"add","-f","approved/.env")
        demo.git(self.source,"commit","-qm","Synthetic filename negative")
        with self.assertRaisesRegex(ValueError,"Secret-like filename"):
            demo.collect_synthetic(self.source,demo.git(self.source,"rev-parse","HEAD"))

    def test_executable_mode_refused(self):
        demo.git(self.source,"update-index","--chmod=+x","approved/decision.md")
        demo.git(self.source,"commit","-qm","Synthetic mode negative")
        with self.assertRaisesRegex(ValueError,"nonregular"):
            demo.collect_synthetic(self.source,demo.git(self.source,"rev-parse","HEAD"))

    def test_case_variant_hold_rejects_through_collector(self):
        folder=self.source/"approved/HeLd"
        folder.mkdir()
        (folder/"record.md").write_text("Invented held content.\n")
        demo.git(self.source,"add","approved/HeLd")
        demo.git(self.source,"commit","-qm","Synthetic case hold")
        with self.assertRaisesRegex(ValueError,"held content"):
            demo.collect_synthetic(self.source,demo.git(self.source,"rev-parse","HEAD"))

    def test_decomposed_unicode_hold_rejects_through_collector(self):
        # Direct index insertion keeps the actual tree path decomposed on APFS.
        # This test has its own source fixture, so no earlier held entry can mask it.
        path="approved/cafe\u0301-private/record.md"
        demo.git(self.source,"config","core.precomposeunicode","false")
        blob=core.git_repo(self.source,"hash-object","-w","--stdin",data=b"Invented held fixture.\n").stdout.decode().strip()
        demo.git(self.source,"update-index","--add","--cacheinfo","100644",blob,path)
        demo.git(self.source,"commit","-qm","Synthetic decomposed Unicode hold")
        revision=demo.git(self.source,"rev-parse","HEAD")
        self.assertIn(path,[e[0] for e in core.source_entries(self.source,revision,["approved/"])])
        with self.assertRaisesRegex(ValueError,"held content"):
            demo.collect_synthetic(self.source,revision)

    def test_all_shipped_secret_signatures_reject_synthetic_bytes(self):
        markers={
            "private-key-block":"-----BEGIN "+"PRIVATE KEY-----",
            "slack-token":"xox"+"b-"+"A"*30,
            "slack-app-token":"x"+"app-1-"+"A"*30,
            "github-token":"gh"+"p_"+"A"*40,
            "anthropic-key":"sk"+"-ant-"+"A"*30,
            "openai-style-key":"s"+"k-"+"A"*40,
            "aws-access-key":"AK"+"IA"+"A"*16,
            "google-api-key":"AI"+"za"+"A"*35,
            "notion-token":"nt"+"n_"+"A"*40,
            "linear-key":"lin_"+"api_"+"A"*30,
            "clickup-token":"pk"+"_123456_"+"A"*20,
        }
        self.assertEqual(set(markers),set(core.SECRET_PATTERNS))
        for name,marker in markers.items():
            with self.subTest(signature=name):
                hits,_=core.scan_bytes("fixture.md",marker.encode(),[])
                self.assertTrue(any(h.startswith(name+":") for h in hits))
                self.assertTrue(all(marker not in h for h in hits))


if __name__ == "__main__":
    unittest.main()
