"""Static UI safety contract; runs headlessly on Linux and Windows.

These checks complement native Windows GUI smoke tests; they do not replace them.
"""
import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "02-Sources" / "odmm_windows_compact_v22811.py"


class WindowsUiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(SOURCE))

    def test_entrypoint_parses(self):
        self.assertIsInstance(self.tree, ast.Module)

    def test_escape_filter_reset_matches_help(self):
        self.assertEqual(self.source.count('root.bind("<Escape>"'), 1)
        self.assertIn('state.set("ALL")', self.source)
        self.assertIn('search.set("")', self.source)
        self.assertIn('state.get() != "ALL"', self.source)
        self.assertIn('text="Effacer les filtres"', self.source)

    def test_view_model_and_worker_used(self):
        self.assertIn("build_jobs_view(", self.source)
        self.assertIn("target=fetch_into_queue", self.source)

    def test_live_demo_and_stale_states_are_explicit(self):
        for marker in ('display_mode[0] = "DEMO"', 'display_mode[0] = "LIVE"',
                       'display_mode[0] = "STALE" if rows else "EMPTY"',
                       'DONNÉES SERVEUR ACTUALISÉES', 'DÉMONSTRATION FICTIVE'):
            self.assertIn(marker, self.source)

    def test_refresh_queue_consumers_acknowledge_tasks(self):
        self.assertGreaterEqual(self.source.count("inbox.task_done()"), 3)
        self.assertIn("if closed[0]: return", self.source)

    def test_no_mutating_migration_controls(self):
        for forbidden in ('text="Lancer migration"', 'text="Exécuter migration"', 'text="Supprimer job"'):
            self.assertNotIn(forbidden, self.source)


if __name__ == "__main__":
    unittest.main()
