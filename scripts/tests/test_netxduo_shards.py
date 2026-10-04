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


def junit(profile, tests=2, failures=0, errors=0, cases=None, child=""):
    cases = tests if cases is None else cases
    body = "".join(f'<testcase name="{profile}::t{i}" status="run">{child if i == 0 else ""}</testcase>'
                   for i in range(cases))
    return (f'<?xml version="1.0"?><testsuite name="{profile}" tests="{tests}" failures="{failures}" '
            f'errors="{errors}">{body}</testsuite>')


TRACEFILE = '{"gcovr/format_version": "0.6", "files": [{"file": "nx_ip_create.c", "lines": []}]}'


def write_shard(root, shard, profiles, failed=0, instrumented=None):
    instrumented = shards.coverage_profiles(shards.canonical_profiles()) if instrumented is None else instrumented
    results = root / f"{shard['result_name']}-results-{SUFFIX}"
    coverage = root / f"{shard['result_name']}-coverage-{SUFFIX}"
    for profile in profiles:
        (results / profile).mkdir(parents=True, exist_ok=True)
        (results / f"{profile}.txt").write_text(
            f"  1/2 Test  #1: x\n{100 if failed == 0 else 50}% tests passed, {failed} tests failed out of 2\n"
            "Total Test time (real) =   1.00 sec\n")
        (results / profile / f"{profile}.xml").write_text(junit(profile))
        if profile in instrumented:
            coverage.mkdir(parents=True, exist_ok=True)
            (coverage / f"{profile}.json").write_text(TRACEFILE)


class NetXDuoShardsTest(unittest.TestCase):
    def setUp(self):
        self.profiles = shards.canonical_profiles()
        self.instrumented = shards.coverage_profiles(self.profiles)
        self.matrix = shards.plan(self.profiles)
        self.directory = Path(tempfile.mkdtemp())
        self.artifacts = self.directory / "artifacts"
        for shard in self.matrix:
            write_shard(self.artifacts, shard, shard["profiles"].split())

    def tearDown(self):
        shutil.rmtree(self.directory)

    def run_check(self, matrix=None):
        return shards.check(matrix or self.matrix, self.artifacts, SUFFIX,
                            self.directory / "coverage", self.directory / "junit", self.profiles,
                            self.instrumented)

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
        self.assertEqual(len(list((self.directory / "coverage").glob("*.json"))), len(self.instrumented))
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

    def coverage_shard(self):
        for shard in self.matrix:
            hit = [p for p in shard["profiles"].split() if p in self.instrumented]
            if hit:
                return shard, hit[0], self.artifacts / f"{shard['result_name']}-coverage-{SUFFIX}"
        self.fail("no shard holds a coverage profile")

    BLOCK = ("if({condition})\n"
             "  target_compile_options(${{PRODUCT}} PRIVATE -fprofile-arcs -ftest-coverage)\n"
             "endif()\n")

    def rule_text(self, *conditions):
        return "\n".join(self.BLOCK.format(condition=c) for c in conditions)

    def test_both_known_spellings_give_the_same_profiles(self):
        old = self.rule_text('CMAKE_BUILD_TYPE MATCHES ".*_coverage"')
        new = self.rule_text('NOT MSVC AND CMAKE_BUILD_TYPE MATCHES ".*_coverage"')
        self.assertEqual(shards.coverage_profiles(self.profiles, text=old), self.instrumented)
        self.assertEqual(shards.coverage_profiles(self.profiles, text=new), self.instrumented)

    def test_unknown_coverage_condition_fails(self):
        with self.assertRaisesRegex(shards.ShardError, "unsupported coverage condition"):
            shards.coverage_profiles(self.profiles, text=self.rule_text(
                'NOT WIN32 AND CMAKE_BUILD_TYPE MATCHES ".*_coverage"'))

    def test_duplicate_coverage_rule_fails(self):
        with self.assertRaisesRegex(shards.ShardError, "found 2"):
            shards.coverage_profiles(self.profiles, text=self.rule_text(
                'CMAKE_BUILD_TYPE MATCHES ".*_coverage"', 'NOT MSVC AND CMAKE_BUILD_TYPE MATCHES ".*_coverage"'))

    def test_missing_coverage_rule_fails(self):
        with self.assertRaisesRegex(shards.ShardError, "found 0"):
            shards.coverage_profiles(self.profiles, text="if(NOT MSVC)\n  add_subdirectory(samples)\nendif()\n")

    def test_coverage_rule_matching_no_profile_fails(self):
        with self.assertRaisesRegex(shards.ShardError, "no profile is instrumented"):
            shards.coverage_profiles(self.profiles, text=self.rule_text(
                'NOT MSVC AND CMAKE_BUILD_TYPE MATCHES ".*_nothing"'))

    def test_coverage_profiles_follow_the_cmake_rule(self):
        self.assertEqual(self.instrumented, [p for p in self.profiles if "_coverage" in p])
        self.assertTrue(set(self.instrumented) < set(self.profiles))

    def test_shard_without_coverage_profile_needs_no_coverage_artifact(self):
        plain = [s for s in self.matrix if not set(s["profiles"].split()) & set(self.instrumented)]
        self.assertTrue(plain)
        for shard in plain:
            self.assertFalse((self.artifacts / f"{shard['result_name']}-coverage-{SUFFIX}").exists())
        self.assertEqual(self.run_check(), len(self.profiles))

    def test_missing_tracefile_fails(self):
        _, profile, coverage = self.coverage_shard()
        (coverage / f"{profile}.json").unlink()
        self.assert_rejected("found 0")

    def test_missing_coverage_artifact_of_a_coverage_shard_fails(self):
        _, _, coverage = self.coverage_shard()
        shutil.rmtree(coverage)
        self.assert_rejected("is missing")

    def test_malformed_tracefile_fails(self):
        _, profile, coverage = self.coverage_shard()
        (coverage / f"{profile}.json").write_text('{"files": [')
        self.assert_rejected("is not valid JSON")

    def test_empty_tracefile_fails(self):
        _, profile, coverage = self.coverage_shard()
        (coverage / f"{profile}.json").write_text('{"gcovr/format_version": "0.6", "files": []}')
        self.assert_rejected("names no source file")

    def test_tracefile_for_an_uninstrumented_profile_fails(self):
        shard = [s for s in self.matrix if not set(s["profiles"].split()) & set(self.instrumented)][0]
        profile = shard["profiles"].split()[0]
        coverage = self.artifacts / f"{shard['result_name']}-coverage-{SUFFIX}"
        coverage.mkdir(parents=True)
        (coverage / f"{profile}.json").write_text(TRACEFILE)
        self.assert_rejected("which is not instrumented")

    def test_no_coverage_profile_at_all_fails(self):
        with self.assertRaises(shards.ShardError):
            shards.check(self.matrix, self.artifacts, SUFFIX, self.directory / "coverage",
                         self.directory / "junit", self.profiles, [])

    def test_failed_test_in_summary_fails(self):
        shard = self.matrix[1]
        write_shard(self.artifacts, shard, [shard["profiles"].split()[0]], failed=1)
        self.assert_rejected("1 of 2 tests failed")

    def replace_junit(self, text, shard_index=4):
        shard = self.matrix[shard_index]
        profile = shard["profiles"].split()[0]
        (self.artifacts / f"{shard['result_name']}-results-{SUFFIX}" / profile / f"{profile}.xml").write_text(
            text.replace("PROFILE", profile))

    def test_consistent_junit_set_passes(self):
        self.replace_junit(junit("PROFILE"))
        self.assertEqual(self.run_check(), len(self.profiles))

    def test_junit_suite_failures_fail(self):
        self.replace_junit(junit("PROFILE", failures=1))
        self.assert_rejected("records 1 failures and 0 errors")

    def test_junit_suite_errors_fail(self):
        self.replace_junit(junit("PROFILE", errors=1))
        self.assert_rejected("records 0 failures and 1 errors")

    def test_junit_testcase_failure_fails(self):
        self.replace_junit(junit("PROFILE", child='<failure message="Failed"/>'))
        self.assert_rejected("has a failure or error")

    def test_junit_testcase_error_fails(self):
        self.replace_junit(junit("PROFILE", child='<error message="Error"/>'))
        self.assert_rejected("has a failure or error")

    def test_summary_total_disagreeing_with_junit_fails(self):
        self.replace_junit(junit("PROFILE", tests=3))
        self.assert_rejected("summary says 0 failed of 2, JUnit says 0 of 3")

    def test_junit_tests_disagreeing_with_testcases_fails(self):
        self.replace_junit(junit("PROFILE", tests=2, cases=1))
        self.assert_rejected("tests=2 but 1 testcase elements")

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
