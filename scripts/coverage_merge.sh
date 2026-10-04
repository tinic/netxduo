#!/bin/bash
##############################################################################
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################

# Union a suite's per-configuration coverage into coverage_report/merged.xml
# and coverage_report/merged/index.html, the report the regression template
# summarises and gates.  Each configuration's coverage.sh run leaves
# coverage_report/<configuration>.json beside its XML.
#
# usage: coverage_merge.sh <suite directory> <gcovr root used by its coverage.sh>

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <suite directory> <gcovr root>" >&2
    exit 2
fi

cd "$1"

shopt -s nullglob
tracefiles=(coverage_report/*.json)
shopt -u nullglob

if [ "${#tracefiles[@]}" -eq 0 ]; then
    echo "coverage_merge.sh: no per-configuration JSON in $PWD/coverage_report." >&2
    exit 1
fi

add_args=()
for tracefile in "${tracefiles[@]}"; do
    add_args+=(--add-tracefile "${tracefile}")
done

mkdir -p coverage_report/merged
gcovr -r "$2" "${add_args[@]}" --xml-pretty --output coverage_report/merged.xml
gcovr -r "$2" "${add_args[@]}" --html --html-details --output coverage_report/merged/index.html

# An empty report reads as 100% to the summary action, so it must fail here.
if ! grep -q "<class " coverage_report/merged.xml; then
    echo "coverage_merge.sh: the merged report contains no files." >&2
    exit 1
fi

echo "coverage_merge.sh: ${#tracefiles[@]} configuration(s):"
for tracefile in "${tracefiles[@]}"; do
    echo "    $(basename "${tracefile}" .json)"
done
