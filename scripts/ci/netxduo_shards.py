#!/usr/bin/env python3
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT

# Portions of this file were generated with AI assistance.

"""Shard the NetX Duo regression suite and check what the shards returned.

plan   derives the shards from BUILD_CONFIGURATIONS in
       test/cmake/netxduo/CMakeLists.txt, the canonical list, and writes them
       as a GitHub Actions matrix.  Nothing is copied by hand: a profile added
       to or removed from the CMake list moves with it.
check  is the aggregate: the planned matrix has to be the one derived now,
       and every profile has to have come back from its shard exactly once,
       with a CTest summary showing no failure and a JUnit report that agrees
       with it and records no failure.  A coverage profile, one the NetX
       CMake instruments, has to return a non-empty gcovr tracefile; any other
       profile has to return none.  It copies the tracefiles and the JUnit
       reports into one place for the coverage union and the test-result
       publication.

At the slowest rate seen on the runners, about 325 s of CTest per profile
(netx_rtcp_basic_test, 2026-10-03), MAX_PROFILES_PER_SHARD profiles take
4 x 360 s = 24 min, inside the shard's 45 min test step and 60 min job.
"""

import argparse
import json
import math
import re
import shutil
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
from classify_changes import REPOSITORY_ROOT, parse_cmake_profiles  # noqa: E402

SUITE = "netxduo"
MAX_PROFILES_PER_SHARD = 4
RESULT_PREFIX = "NetXDuo-shard-"
SUMMARY_LINE = re.compile(r"^\s*\d+% tests passed, (\d+) tests failed out of (\d+)")


# The NetX CMake instruments a profile only when its name matches this, in
# the block after "# Coverage"; TX_COVERAGE does not change that.
COVERAGE_RULE = re.compile(r'#\s*Coverage\s*\n\s*if\s*\(\s*CMAKE_BUILD_TYPE\s+MATCHES\s+"([^"]+)"\s*\)')


class ShardError(Exception):
    """A shard plan or a shard result that cannot be accepted."""


def canonical_profiles(repository_root=REPOSITORY_ROOT):
    profiles = parse_cmake_profiles(repository_root / "test" / "cmake" / SUITE / "CMakeLists.txt")
    if not profiles or len(profiles) != len(set(profiles)):
        raise ShardError("BUILD_CONFIGURATIONS is empty or lists a profile twice")
    return profiles


def coverage_profiles(profiles, repository_root=REPOSITORY_ROOT):
    """The profiles the NetX CMake instruments, by its own rule."""
    text = (repository_root / "test" / "cmake" / SUITE / "CMakeLists.txt").read_text()
    rules = COVERAGE_RULE.findall(text)
    if len(rules) != 1:
        raise ShardError(f"expected one coverage rule in the {SUITE} CMakeLists.txt, found {len(rules)}")
    # CMake MATCHES is an unanchored search.
    instrumented = [profile for profile in profiles if re.search(rules[0], profile)]
    if not instrumented:
        raise ShardError("no profile is instrumented for coverage, so the union would be empty")
    return instrumented


def check_tracefile(tracefile):
    """A gcovr JSON tracefile that names at least one file."""
    try:
        data = json.loads(tracefile.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ShardError(f"{tracefile.name} is not valid JSON: {error}") from error
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, list) or not files:
        raise ShardError(f"{tracefile.name} names no source file")


def plan(profiles):
    """Every profile once, round robin over the fewest shards that hold them."""
    count = math.ceil(len(profiles) / MAX_PROFILES_PER_SHARD)
    shards = [profiles[index::count] for index in range(count)]
    matrix = [
        {
            "name": str(index + 1),
            "result_name": f"{RESULT_PREFIX}{index + 1}",
            "profiles": " ".join(shard),
        }
        for index, shard in enumerate(shards)
    ]
    validate_plan(matrix, profiles)
    return matrix


def validate_plan(matrix, profiles):
    planned = [profile for shard in matrix for profile in shard["profiles"].split()]
    if len(planned) != len(set(planned)):
        raise ShardError("a profile is planned in more than one shard")
    if set(planned) != set(profiles):
        missing = sorted(set(profiles) - set(planned))
        extra = sorted(set(planned) - set(profiles))
        raise ShardError(f"plan does not match BUILD_CONFIGURATIONS: missing {missing}, unknown {extra}")
    if any(len(shard["profiles"].split()) > MAX_PROFILES_PER_SHARD for shard in matrix):
        raise ShardError("a shard holds more profiles than MAX_PROFILES_PER_SHARD")
    names = [shard["result_name"] for shard in matrix]
    if len(names) != len(set(names)):
        raise ShardError("two shards share a result name")


def check_junit(junit, failed, total):
    """The JUnit report has to record no failure and agree with the summary."""
    root = ElementTree.parse(junit).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    if len(suites) != 1:
        raise ShardError(f"{junit.name} has {len(suites)} testsuites, not one")
    suite = suites[0]
    tests, failures, errors = (int(suite.get(name, "0")) for name in ("tests", "failures", "errors"))
    if tests == 0:
        raise ShardError(f"{junit.name} reports no tests")
    if failures or errors:
        raise ShardError(f"{junit.name}: testsuite records {failures} failures and {errors} errors")
    cases = suite.findall("testcase")
    if len(cases) != tests:
        raise ShardError(f"{junit.name}: tests={tests} but {len(cases)} testcase elements")
    bad = [case.get("name", "?") for case in cases
           if case.find("failure") is not None or case.find("error") is not None]
    if bad:
        raise ShardError(f"{junit.name}: testcase {bad[0]} has a failure or error ({len(bad)} in all)")
    if (failed, total) != (failures + errors, tests):
        raise ShardError(f"{junit.name}: summary says {failed} failed of {total}, "
                         f"JUnit says {failures + errors} of {tests}")


def _one(directory, pattern, what):
    found = sorted(directory.rglob(pattern))
    if len(found) != 1:
        raise ShardError(f"{what}: expected exactly one {pattern} in {directory.name}, found {len(found)}")
    return found[0]


def check(matrix, artifacts, run_suffix, coverage_out, junit_out, profiles, instrumented):
    """Fail on any missing shard, missing or duplicate profile, or missing report."""
    if matrix != plan(profiles):
        raise ShardError("the planned matrix is not the one BUILD_CONFIGURATIONS gives now")
    if not instrumented or not set(instrumented) <= set(profiles):
        raise ShardError("the coverage profiles are empty or not all in BUILD_CONFIGURATIONS")
    errors = []
    seen = {}
    coverage_out.mkdir(parents=True, exist_ok=True)
    junit_out.mkdir(parents=True, exist_ok=True)
    for shard in matrix:
        assigned = shard["profiles"].split()
        results = artifacts / f"{shard['result_name']}-results-{run_suffix}"
        coverage = artifacts / f"{shard['result_name']}-coverage-{run_suffix}"
        # A shard with no coverage profile collects no tracefile, and the
        # worker uploads no coverage artifact for it.
        expected = [results] + ([coverage] if set(assigned) & set(instrumented) else [])
        absent = [directory for directory in expected if not directory.is_dir()]
        for directory in absent:
            errors.append(f"shard {shard['name']}: artifact {directory.name} is missing")
        if absent:
            continue

        # Nothing beyond the assigned profiles may come back from a shard.
        returned = {path.stem for path in results.glob("*.txt")}
        traced = {path.stem for path in coverage.rglob("*.json")} if coverage.is_dir() else set()
        returned |= traced
        for stray in sorted(returned - set(assigned)):
            errors.append(f"shard {shard['name']}: reports for {stray}, which it was not assigned")
        for uninstrumented in sorted((traced & set(assigned)) - set(instrumented)):
            errors.append(f"shard {shard['name']}: a tracefile for {uninstrumented}, which is not instrumented")

        for profile in assigned:
            if profile in seen:
                errors.append(f"{profile}: reported by shard {seen[profile]} and shard {shard['name']}")
                continue
            seen[profile] = shard["name"]
            try:
                summary = results / f"{profile}.txt"
                if not summary.is_file():
                    raise ShardError(f"no CTest summary {summary.name}")
                lines = [SUMMARY_LINE.match(line) for line in summary.read_text(errors="replace").splitlines()]
                lines = [match for match in lines if match]
                if len(lines) != 1:
                    raise ShardError(f"{summary.name} has {len(lines)} result lines, not one")
                failed, total = int(lines[0].group(1)), int(lines[0].group(2))
                if failed != 0 or total == 0:
                    raise ShardError(f"{summary.name}: {failed} of {total} tests failed")
                junit = results / profile / f"{profile}.xml"
                if not junit.is_file():
                    raise ShardError(f"no JUnit report {profile}/{junit.name}")
                check_junit(junit, failed, total)
                if profile in instrumented:
                    tracefile = _one(coverage, f"{profile}.json", "coverage")
                    check_tracefile(tracefile)
                    shutil.copyfile(tracefile, coverage_out / tracefile.name)
                shutil.copyfile(junit, junit_out / junit.name)
            except (ShardError, ElementTree.ParseError, ValueError) as error:
                errors.append(f"shard {shard['name']}, {profile}: {error}")

    for profile in profiles:
        if profile not in seen:
            errors.append(f"{profile}: no shard returned it")
    if errors:
        raise ShardError("\n".join(errors))
    return len(seen)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--github-output", type=Path)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--matrix", required=True, help="the plan job's matrix, as JSON")
    check_parser.add_argument("--artifacts", required=True, type=Path)
    check_parser.add_argument("--run-suffix", required=True, help="<run_id>-<run_attempt>")
    check_parser.add_argument("--coverage-out", required=True, type=Path)
    check_parser.add_argument("--junit-out", required=True, type=Path)
    arguments = parser.parse_args(argv)

    try:
        profiles = canonical_profiles()
        if arguments.command == "plan":
            matrix = plan(profiles)
            rendered = json.dumps(matrix, separators=(",", ":"))
            if arguments.github_output:
                with arguments.github_output.open("a", encoding="utf-8") as output:
                    output.write(f"matrix={rendered}\n")
            print(f"{len(profiles)} profiles in {len(matrix)} shards:")
            for shard in matrix:
                print(f"  {shard['result_name']}: {shard['profiles']}")
            return 0
        instrumented = coverage_profiles(profiles)
        count = check(json.loads(arguments.matrix), arguments.artifacts, arguments.run_suffix,
                      arguments.coverage_out, arguments.junit_out, profiles, instrumented)
        print(f"all {count} profiles returned once, with summary and JUnit report; "
              f"tracefiles for the {len(instrumented)} coverage profiles: {' '.join(instrumented)}")
        return 0
    except ShardError as error:
        print(f"netxduo_shards.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
