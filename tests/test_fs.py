"""Focused tests for per-session fake filesystem isolation.

These validate that each session receives an independent in-memory fake
filesystem and working directory, and that mutating one session's state never
affects another's. They exercise the dependency-free primitives in
``honeypot.fs`` and the session-owned state in ``honeypot.session``.
"""

import unittest

from honeypot.fs import create_filesystem, get_dir
from honeypot.session import Session


def home_user1(fs):
    return get_dir("/home/user1", fs)


class TestFilesystemIsolation(unittest.TestCase):
    # --- Test 1: independent initial state ---------------------------------
    def test_independent_initial_state(self):
        a = create_filesystem()
        b = create_filesystem()
        self.assertEqual(a, b)          # same initial structure
        self.assertIsNot(a, b)          # but distinct top-level objects

    def test_sessions_have_distinct_filesystems(self):
        a = Session(source_ip="10.0.0.1")
        b = Session(source_ip="10.0.0.2")
        self.assertIsNot(a.fake_filesystem, b.fake_filesystem)
        self.assertEqual(a.fake_filesystem, b.fake_filesystem)  # same shape

    # --- Test 2: file isolation --------------------------------------------
    def test_file_isolation(self):
        a = create_filesystem()
        b = create_filesystem()
        home_user1(a)["a.txt"] = ""
        self.assertIn("a.txt", home_user1(a))
        self.assertNotIn("a.txt", home_user1(b))  # B cannot see A's file

    # --- Test 3: content isolation -----------------------------------------
    def test_content_isolation(self):
        a = create_filesystem()
        b = create_filesystem()
        home_user1(a)["secret.txt"] = "s3cret content"
        self.assertEqual(home_user1(a)["secret.txt"], "s3cret content")
        self.assertNotIn("secret.txt", home_user1(b))  # B cannot read A's file

    # --- Test 4: directory isolation ---------------------------------------
    def test_directory_isolation(self):
        a = create_filesystem()
        b = create_filesystem()
        home_user1(a)["attackerdir"] = {}
        self.assertIn("attackerdir", home_user1(a))
        self.assertNotIn("attackerdir", home_user1(b))

    # --- Test 5: deletion isolation ----------------------------------------
    def test_deletion_isolation(self):
        a = create_filesystem()
        b = create_filesystem()
        # Both start with notes.txt inherited from the initial structure.
        self.assertIn("notes.txt", home_user1(a))
        self.assertIn("notes.txt", home_user1(b))
        del home_user1(a)["notes.txt"]  # A deletes a file
        self.assertNotIn("notes.txt", home_user1(a))
        self.assertIn("notes.txt", home_user1(b))  # B unaffected

    # --- Test 6: working-directory isolation -------------------------------
    def test_working_directory_isolation(self):
        a = Session(source_ip="10.0.0.1")
        b = Session(source_ip="10.0.0.2")
        # A changes directory; B must retain the default.
        a.cwd = "/home"
        self.assertEqual(a.cwd, "/home")
        self.assertEqual(b.cwd, "/home/user1")
        # A's cd must never leak into B.
        self.assertNotEqual(a.cwd, b.cwd)

    # --- Test 7: simultaneous sessions -------------------------------------
    def test_simultaneous_sessions_independent(self):
        a = Session(source_ip="10.0.0.1")
        b = Session(source_ip="10.0.0.2")
        # A writes under /home/user1.
        home_user1(a.fake_filesystem)["from_a.txt"] = "A data"
        home_user1(a.fake_filesystem)["dir_a"] = {}
        a.cwd = "/home"
        # B writes under /home/user1 too.
        home_user1(b.fake_filesystem)["from_b.txt"] = "B data"
        # Cross-check: neither sees the other's entries.
        self.assertNotIn("from_a.txt", home_user1(b.fake_filesystem))
        self.assertNotIn("dir_a", home_user1(b.fake_filesystem))
        self.assertNotIn("from_b.txt", home_user1(a.fake_filesystem))
        self.assertEqual(a.cwd, "/home")
        self.assertEqual(b.cwd, "/home/user1")

    # --- Nested/with in-memory tree safety ----------------------------------
    def test_nested_objects_are_deep_copied(self):
        a = create_filesystem()
        b = create_filesystem()
        # Mutate a deeply nested subdir in A; B's equivalent must be unaffected.
        get_dir("/home/user1/Documents", a)["x.txt"] = "x"
        self.assertIn("x.txt", get_dir("/home/user1/Documents", a))
        self.assertNotIn("x.txt", get_dir("/home/user1/Documents", b))


if __name__ == '__main__':
    unittest.main()