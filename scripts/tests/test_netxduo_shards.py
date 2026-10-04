#!/usr/bin/env python3
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT

# Portions of this file were generated with AI assistance.

"""scripts/ci/netxduo_shards.py: the plan against BUILD_CONFIGURATIONS, and
the aggregate check against a complete set of shard artifacts and against
each way one can be incomplete."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ci"))
import netxduo_shards as shards  # noqa: E402

SUFFIX = "1234-1"


def write_shard(root, shard, profiles, failed=0):
    results = root / f"{shard['result_name']}-results-{SUFFIX}"
    coverage = root / f"{shard['result_name']}-coverage-{SUFFIX}"
    for profile in profiles:
        (results / profile).mkdir(parents=True, exist_ok=True)
        (results / f"{profile}.txt").write_text(
            f"  1/2 Test  #1: x\n{100 if failed == 0 else 50}% tests passed, {failed} tests failed out of 2\n"
            "Total Test time (real) =   1.00 sec\n")
        (results / profile / f"{profile}.xml").write_text(
            f'<?xml version="1.0"?><testsuite name="{profile}" tests="2" failures="0"></testsuite>')
        coverage.mkdir(parents=True, exist_ok=True)
        (coverage / f"{profile}.json").write_text("{}")


class NetXDuoShardsTest(unittest.TestCase):
    def setUp(self):
        self.profiles = shards.canonical_profiles()
        self.matrix = shards.plan(self.profiles)
        self.directory = Path(tempfile.mkdtemp())
        self.artifacts = self.directory / "artifacts"
        for shard in self.matrix:
            write_shard(self.artifacts, shard, shard["profiles"].split())

    def tearDown(self):
        shutil.rmtree(self.directory)

    def run_check(self, matrix=None):
        return shards.check(matrix or self.matrix, self.artifacts, SUFFIX,
                            self.directory / "coverage", self.directory / "junit", self.profiles)

    def assert_rejected(self, text):
        with self.assertRaises(shards.ShardError) as caught:
            self.run_check()
        self.assertIn(text, str(caught.exception))

    def test_plan_is_an_exact_partition(self):
        planned = [p for shard in self.matrix for p in shard["profiles"].split()]
        self.assertEqual(sorted(planned), sorted(self.profiles))
        self.assertEqual(len(planned), len(set(planned)))
        self.assertTrue(all(len(s["profiles"].split()) <= shards.MAX_PROFILES_PER_SHARD for s in self.matrix))

    def test_complete_artifacts_pass(self):
        self.assertEqual(self.run_check(), len(self.profiles))
        self.assertEqual(len(list((self.directory / "coverage").glob("*.json"))), len(self.profiles))
        self.assertEqual(len(list((self.directory / "junit").glob("*.xml"))), len(self.profiles))

    def test_missing_shard_artifact_fails(self):
        shard = self.matrix[3]
        shutil.rmtree(self.artifacts / f"{shard['result_name']}-coverage-{SUFFIX}")
        self.assert_rejected("is missing")

    def test_missing_profile_summary_fails(self):
        shard = self.matrix[0]
        profile = shard["profiles"].split()[1]
        (self.artifacts / f"{shard['result_name']}-results-{SUFFIX}" / f"{profile}.txt").unlink()
        self.assert_rejected("no CTest summary")

    def test_missing_junit_fails(self):
        shard = self.matrix[2]
        profile = shard["profiles"].split()[0]
        (self.artifacts / f"{shard['result_name']}-results-{SUFFIX}" / profile / f"{profile}.xml").unlink()
        self.assert_rejected("no JUnit report")

    def test_missing_tracefile_fails(self):
        shard = self.matrix[5]
        profile = shard["profiles"].split()[-1]
        (self.artifacts / f"{shard['result_name']}-coverage-{SUFFIX}" / f"{profile}.json").unlink()
        self.assert_rejected("found 0")

    def test_failed_test_in_summary_fails(self):
        shard = self.matrix[1]
        write_shard(self.artifacts, shard, [shard["profiles"].split()[0]], failed=1)
        self.assert_rejected("1 of 2 tests failed")

    def test_profile_returned_by_a_second_shard_fails(self):
        stray = self.matrix[0]["profiles"].split()[0]
        write_shard(self.artifacts, self.matrix[1], [stray])
        self.assert_rejected("which it was not assigned")

    def test_tampered_plan_fails(self):
        matrix = json.loads(json.dumps(self.matrix))
        matrix[-1]["profiles"] = " ".join(matrix[-1]["profiles"].split()[:-1])
        with self.assertRaises(shards.ShardError):
            self.run_check(matrix)

    def test_duplicate_in_plan_fails(self):
        matrix = json.loads(json.dumps(self.matrix))
        matrix[0]["profiles"] += " " + matrix[1]["profiles"].split()[0]
        with self.assertRaises(shards.ShardError):
            shards.validate_plan(matrix, self.profiles)


if __name__ == "__main__":
    unittest.main()
