#!/bin/bash
# Copyright (c) 2026 Eclipse ThreadX contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# Only configure the disposable GitHub runner, never a developer's host.
if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    exit 0
fi

# The Azure Ubuntu mirror repeatedly stalled multiarch package downloads until
# the install step's ten-minute limit. Keep the same signed Ubuntu repositories
# and transport, using their standard archive instead of that mirror.
sudo python3 - <<'PY'
from pathlib import Path

sources = [Path('/etc/apt/sources.list')]
sources.extend(Path('/etc/apt/sources.list.d').glob('*.list'))
sources.extend(Path('/etc/apt/sources.list.d').glob('*.sources'))
for source in sources:
    if not source.is_file():
        continue
    original = source.read_text()
    updated = original.replace('://azure.archive.ubuntu.com/ubuntu',
                               '://archive.ubuntu.com/ubuntu')
    if updated != original:
        source.write_text(updated)
        print('Using standard Ubuntu archive in ' + str(source))
PY

# Bound a stalled request and retry it. Exhausted downloads still fail install.
printf '%s\n' \
    'Acquire::Retries "3";' \
    'Acquire::http::Timeout "60";' \
    'Acquire::https::Timeout "60";' |
    sudo tee /etc/apt/apt.conf.d/80netxduo-ci-network >/dev/null
