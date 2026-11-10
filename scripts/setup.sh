#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/environment.sh"
if [[ $# -gt 1 || (${1:-} != "" && ${1:-} != "--check") ]]; then
  echo 'Usage: ./scripts/setup.sh [--check]' >&2; exit 2
fi
node -e 'if(process.versions.node!=="24.21.0")throw Error("Node 24.21.0 required")'
circom --version | python3 -c 'import sys; assert "2.2.3" in sys.stdin.read(), "Circom 2.2.3 required"'
python3 -c 'import sys; assert (3,11)<=sys.version_info[:2]<(3,13), "Python 3.11 or 3.12 required"'
if [[ ${1:-} != '--check' ]]; then
  npm ci --ignore-scripts --no-audit --no-fund
  if [[ ! -d .venv ]]; then python3 -m venv .venv; fi
  .venv/bin/python -m pip install --cache-dir .cache/pip -r requirements.txt
  export PATH="$release_root/.venv/bin:$PATH"
fi
node --input-type=module -e 'import {createRequire} from "node:module"; import {readFileSync} from "node:fs"; import {dirname,join} from "node:path"; const r=createRequire(import.meta.url);const wanted=JSON.parse(readFileSync("package.json")).devDependencies; for(const [name,version] of Object.entries(wanted)){let p;try{p=r.resolve(name+"/package.json")}catch{let d=dirname(r.resolve(name));for(;;){try{const candidate=join(d,"package.json");const j=JSON.parse(readFileSync(candidate));if(j.name===name){p=candidate;break}}catch{}const up=dirname(d);if(up===d)throw Error(name);d=up}}if(JSON.parse(readFileSync(p)).version!==version)throw Error("Dependency version mismatch: "+name)}'
python3 -c 'import importlib.metadata as m; expected={"eth-hash":"0.8.0","pycryptodome":"3.24.1","pytest":"9.1.1","ruff":"0.16.10"}; assert all(m.version(k)==v for k,v in expected.items()), "Python dependency version mismatch"'
echo 'PASS: installed toolchain and locked dependencies'
