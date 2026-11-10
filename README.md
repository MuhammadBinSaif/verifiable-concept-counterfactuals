# Verifiable Concept-Level Counterfactual Explanations

Optimized two-stage ZKP verification code for concept-state certification and counterfactual explanation verification, with blockchain-based certification and certified-state reuse.

## Installation

Install Node.js **24.21.0**, Circom **2.2.3**, and Python **3.11 or 3.12**. From the repository root:

```bash
./scripts/setup.sh
./scripts/setup.sh --check
source .venv/bin/activate
```

JavaScript dependencies are pinned in `package-lock.json`; Python dependencies and distribution hashes are pinned in `requirements.lock`. These include snarkjs 0.7.6, circomlib 2.0.5, circomlibjs 0.1.7, solc 0.8.37, and Hardhat 3.18.1.

## Execute

```bash
./scripts/run_demo.sh --config s1
./scripts/run_demo.sh --config s2
./scripts/run_demo.sh --config s3
```

Demos and benchmarks load the provided `data/sN/original.json` files by default. Each contains twenty recorded explanation candidates. Dataset checksums and configuration identities are checked before execution; no data-generation step is required.

A demo compiles or checks cached circuits, prepares or reuses verified development keys, and executes one Stage A certification and two Stage B explanations. Use `--explanations N` for 2..20 explanations and a new `--run-id NAME` to retain separate outputs.

To compile or check witnesses separately, select the required configuration:

```bash
python -m src.protocol.cli compile --config s1
python -m src.protocol.cli validate --config s1
```

Use `--help` with either execution script for available options. Compilation, setup and proving enforce resource checks.

## Optional local artifacts

Compatible local artifacts can be checked and imported before running a demo:

```bash
python scripts/import_artifacts.py --manifest .artifacts/import_manifest.json --check
python scripts/import_artifacts.py --manifest .artifacts/import_manifest.json --verify
```

The manifest uses `schema: 1` and an `entries` array. Required fields and compatibility checks are defined in `src/protocol/artifacts.py`. Keep manifests with local paths under ignored `.artifacts/`. Importing artifacts is optional; the demo can prepare its own development keys.

## Tests

```bash
python -m pytest
npm test
npm run typecheck
python -m ruff check --select F --no-cache src data tests scripts
python scripts/audit_release.py
```

## Optional benchmarks

```bash
./scripts/run_benchmark.sh --config s1 --a-trials 3 --b-trials 20
./scripts/run_benchmark.sh --config s2 --a-trials 3 --b-trials 20
./scripts/run_benchmark.sh --config s3 --a-trials 3 --b-trials 20
```

A trials support 1..1000 samples; B trials support 2..20 candidates. Benchmarks use the provided data by default.

## Outputs

Executions create ignored `runs/CONFIG/RUN_ID/` directories containing `measurements.json`, `measurements.csv`, `blockchain.json`, and `blockchain_runs.csv`. Compiled circuits, keys and private openings are stored in ignored runtime directories. Preserve these directories locally and keep them out of Git.

Generated or imported Groth16 phase-2 keys are **DEV_INSECURE** and do not establish production trusted-setup security. Do not publish private witness openings or production records. See `LICENSE` and `THIRD_PARTY_NOTICES.md` for licensing and attribution.
