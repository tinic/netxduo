#!/bin/bash
##############################################################################
# Copyright (c) 2024 Microsoft Corporation
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################


set -e

cd $(dirname $0)

if [ "$1" = "--merge" ]; then
    exec ../../../scripts/coverage_merge.sh "$PWD" ../../../common/src
fi

root_path=$(cd ../../../common/src; pwd)
mkdir -p coverage_report/$1
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --json coverage_report/$1.json --xml-pretty --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/common/src -r ../../../common/src -e $root_path/nx_ram_network_driver.c --html --html-details --output coverage_report/$1/index.html
