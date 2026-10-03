"""Regression tests for evidence boundaries, freshness, integrity and escaping."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from common import json_lines
from export_evidence import select_alerts, require_coverage
from generate_events import events
from triage import render_html, summarize, verify_manifest, verify_hashes


class EvidenceTests(unittest.TestCase):
    def row(self):
        return {
            "timestamp": "2026-09-28T12:00:00+00:00", "id": "unique-1",
            "rule": {"id": "100103", "description": "fixture"},
            "agent": {"id": "000", "name": "soc-manager"},
            "data": events("current", timestamp="2026-09-28T12:00:00+00:00")[8],
        }

    def select(self, rows):
        return select_alerts(rows, "2026-09-28T11:59:59+00:00", "current", {})

    def test_stale_and_other_run_cannot_approve_new_execution(self):
        old = self.row()
        old["timestamp"] = "2026-09-28T11:00:00+00:00"
        other = self.row()
        other["data"]["run_id"] = "previous"
        self.assertEqual(self.select([old, other]), [])

    def test_duplicate_alert_and_unrelated_metadata_are_not_published(self):
        row = self.row()
        row["data"]["internal_secret"] = "do-not-export"
        selected = self.select([row, copy.deepcopy(row)])
        self.assertEqual(len(selected), 1)
        self.assertNotIn("internal_secret", selected[0]["data"])

    def test_wrong_origin_and_agent_are_rejected(self):
        row = self.row()
        row["data"]["origin"] = "real"
        self.assertEqual(self.select([row]), [])
        row = self.row()
        row["agent"]["name"] = "unrelated-server"
        self.assertEqual(self.select([row]), [])

    def test_fim_hash_mismatch_fails_closed(self):
        row = self.row()
        row["rule"]["id"] = "100105"
        row["agent"] = {"id": "001", "name": "soc-endpoint"}
        row["syscheck"] = {"path": "/lab/protected/current.conf", "event": "modified",
                           "sha256_before": "old", "sha256_after": "unexpected"}
        with self.assertRaises(ValueError):
            select_alerts([row], "2026-09-28T11:59:59+00:00", "current",
                          {"/lab/protected/current.conf": {"sha256_after": "expected"}})

    def test_missing_coverage_is_not_success(self):
        with self.assertRaises(ValueError):
            require_coverage(self.select([self.row()]))

    def test_deleted_file_uses_last_known_hash_with_deleted_event(self):
        row = self.row()
        row["rule"]["id"] = "100114"
        row["agent"] = {"id": "001", "name": "soc-endpoint"}
        row["syscheck"] = {"path": "/lab/protected/current.conf", "event": "deleted",
                           "sha256_after": "baseline-hash"}
        selected = select_alerts([row], "2026-09-28T11:59:59+00:00", "current",
                                 {"/lab/protected/current.conf": {"sha256_after": "baseline-hash"}})
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["syscheck"]["event"], "deleted")

    def test_invalid_json_and_naive_timestamps_are_not_silently_accepted(self):
        for text in ["not-json", "[]"]:
            with self.assertRaises(ValueError):
                json_lines(text)
        row = self.row()
        row["timestamp"] = "2026-09-28T12:00:00"
        with self.assertRaises(ValueError):
            self.select([row])

    def test_generator_remains_labelled_and_deterministic(self):
        rows = events("reference", "2026-09-28T12:00:00+00:00")
        self.assertEqual(rows, events("reference", "2026-09-28T12:00:00+00:00"))
        self.assertEqual(len(rows), 11)
        self.assertEqual(len({row["event_id"] for row in rows}), 11)
        self.assertTrue(all(row["origin"] == "synthetic" for row in rows))

    def test_triage_rejects_corrupted_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.jsonl"
            path.write_text("bad-data\n", encoding="utf-8", newline="\n")
            with self.assertRaises(ValueError):
                summarize(path)

    def test_static_report_escapes_untrusted_event_text(self):
        row = self.row()
        row["rule"]["description"] = "<script>alert(1)</script>"
        result = render_html(self.select([row]), {
            "engine_version": "4.14.8", "run_id": "test", "started_at": "start", "completed_at": "end",
        }, [{"case": "<img src=x onerror=alert(1)>", "passed": True}])
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&lt;img", result)

    def test_empty_pass_manifest_is_not_a_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "manifest.json").write_text('{"status":"passed","artifacts_sha256":{}}', encoding="utf-8", newline="\n")
            with self.assertRaises(ValueError):
                verify_manifest(root)

    def test_snapshot_integrity_detects_tampering_and_path_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "artifact.txt").write_bytes(b"original")
            manifest = {"status": "passed", "artifacts_sha256": {"artifact.txt": hashlib.sha256(b"original").hexdigest()}}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8", newline="\n")
            verify_hashes(root, manifest["artifacts_sha256"])
            (root / "artifact.txt").write_bytes(b"modified")
            with self.assertRaises(ValueError):
                verify_hashes(root, manifest["artifacts_sha256"])
            manifest["artifacts_sha256"] = {"../outside.txt": "irrelevant"}
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8", newline="\n")
            with self.assertRaises(ValueError):
                verify_manifest(root)


if __name__ == "__main__":
    unittest.main()
