import re
import shutil
import unittest
from pathlib import Path

from backtest_vpn import pseudonym


class PseudonymTest(unittest.TestCase):
    def test_determinism_and_format(self):
        key = bytes.fromhex("00" * 32)
        pz = pseudonym.Pseudonymizer(key)
        self.assertEqual(pz.pseudonymize(" f123 "), pz.pseudonymize("F123"))
        self.assertRegex(pz.pseudonymize("F123"), r"^U-[0-9a-f]{12}$")

    def test_key_creation_gitignore(self):
        root = Path("tests/.scratch_pseudonym")
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        key = pseudonym.load_or_create_key(root / ".pseudonym_key", repo_dir=root)
        self.assertEqual(len(key), 32)
        self.assertIn(".pseudonym_key", (root / ".gitignore").read_text(encoding="utf-8"))
        shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
