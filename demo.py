"""Exercise the selected transaction against two temporary synthetic Git repos."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import workspace_core as core


def git(repo, *args):
    return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                                   stderr=subprocess.PIPE).decode().strip()


def fixture(root):
    source = root / "synthetic-source"
    source.mkdir()
    git(source, "init", "-q", "-b", "main")
    git(source, "config", "user.name", "Synthetic author")
    git(source, "config", "user.email", "fixture@example.invalid")
    (source / "approved").mkdir()
    (source / "approved/decision.md").write_text("Synthetic decision: test before release.\n")
    (source / "excluded").mkdir()
    (source / "excluded/record.md").write_text("Invented excluded sentinel.\n")
    git(source, "add", "approved", "excluded")
    git(source, "commit", "-qm", "Synthetic source")
    revision = git(source, "rev-parse", "HEAD")
    (source / "approved/decision.md").write_text("Uncommitted sentinel must stay out.\n")
    (source / "approved/untracked.md").write_text("Untracked sentinel must stay out.\n")
    target = root / "employee.git"
    subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(target)], check=True)
    return source, target, revision


def collect_synthetic(source, revision):
    """Finite demo policy. Production collection and live grants are not exported."""
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("An exact synthetic source commit is required")
    entries = core.source_entries(source, revision, ["approved/"])
    for name, mode, kind, oid in entries:
        if not name.startswith("approved/") or mode != "100644" or kind != "blob":
            raise ValueError("Synthetic policy rejects nonregular or out-of-scope entries")
        if core.is_under_folded(name, ("approved/held/", "approved/caf\u00e9-private/")):
            raise ValueError("Synthetic policy rejects held content")
        if core.secret_filename_hits([name]):
            raise ValueError("Secret-like filename")
    blobs = core.read_blobs(source, [e[3] for e in entries])
    files = []
    for name, mode, kind, oid in entries:
        data = blobs[oid]
        if core.scan_bytes(name, data, [])[0]:
            raise ValueError("Secret-like bytes")
        files.append((name, data))
    layer = {"id": "synthetic-business", "title": "Synthetic business reader"}
    manifest = {"built_at": "2026-11-13T00:00:00+00:00", "source_uncommitted_entries": 2,
                "source_commit": revision, "file_count": len(files), "layers_version": "fixture-only",
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in files}}
    return {"layer": layer, "manifest": manifest, "files": files,
            "entries": files + core.generated_entries(layer, manifest)}


def main():
    with tempfile.TemporaryDirectory() as temporary:
        source, target, revision = fixture(Path(temporary))
        collection = collect_synthetic(source, revision)
        first = core._commit_collected(target, collection)
        second = core._commit_collected(target, collection)
        parents = git(target, "rev-list", "--parents", "-n", "1", first["commit"]).split()
        print(json.dumps({"synthetic": True, "selected_files": len(collection["files"]),
                          "fresh_root": len(parents) == 1, "repeat_is_noop": not second["committed"],
                          "source_commit_is_parent": revision in parents[1:],
                          "live_employee_grants": False, "network_transport_included": False}, indent=2))


if __name__ == "__main__":
    main()
