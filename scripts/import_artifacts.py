"""Verify and import a complete local development-artifact set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.protocol.artifacts import run_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true', help='Check hashes, layout and source identity without importing keys')
    group.add_argument('--verify', action='store_true', help='Run full setup/key verification and import; this is the default')
    args = parser.parse_args()
    result = run_manifest(args.manifest, check_only=args.check)
    print(json.dumps(dict(status=result['status'], check_only=result['check_only'],
        entries=[dict(configuration=entry['configuration'], stage=entry['stage'],
            status=entry['status'], key_verification=entry['key_verification'], imported=entry['imported'])
            for entry in result['entries']], network_contacted=False), sort_keys=True))


if __name__ == '__main__':
    main()
