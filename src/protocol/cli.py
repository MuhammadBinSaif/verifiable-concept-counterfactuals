"""Optimized protocol demonstrations and configurable measurements."""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import socket
import subprocess
import time
from src.config import ROOT, load_config
from src import fixtures
from src.protocol.engine import compile_stage, negatives, prove, setup_stage, witness
from src.protocol.io import contained, load, output_file, rel, save, sha
from src.protocol.measure import measure
from src.protocol.resources import ResourceBlocked, capacity


def metadata(cfg):
    versions = {}
    for name, command in [('node', ['node', '--version']), ('circom', ['circom', '--version'])]:
        versions[name] = subprocess.check_output(command, text=True).strip()
    versions['python'] = platform.python_version()
    versions['node_packages'] = load(ROOT / 'package.json')['devDependencies']
    return dict(configuration=cfg['id'], architecture=cfg['architecture'], seed=cfg['seed'],
        tools=versions, hardware=dict(os=platform.platform(), machine=platform.machine(),
        logical_cpus=os.cpu_count(), host=socket.gethostname()),
        security='DEV_INSECURE', source_relation=cfg['expected'],
        units=dict(wall_seconds='seconds', cpu_seconds='seconds', peak_rss_bytes='bytes',
                   key_bytes='bytes', constraints='R1CS constraints', gas='EVM gas'))


def rows_csv(path, rows):
    fields = ['stage', 'trial', 'status', 'prove_seconds', 'verify_seconds', 'witness_seconds',
        'r1cs_check_seconds', 'peak_rss_bytes', 'cpu_seconds', 'key_bytes']
    with output_file(path).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(stage=row['stage'], trial=row['trial'], status=row['status'],
                prove_seconds=row['prove']['wall_seconds'], verify_seconds=row['verify']['wall_seconds'],
                witness_seconds=row['witness']['wall_seconds'], r1cs_check_seconds=row['r1cs_check']['wall_seconds'],
                peak_rss_bytes=row['prove']['peak_rss_bytes'], cpu_seconds=row['prove']['cpu_seconds'],
                key_bytes=row['key_bytes']))


def run(args):
    cfg = load_config(args.config)
    name = args.run_id or time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name):
        raise ValueError('Run identifier must be a simple directory name')
    root = contained(ROOT / 'runs' / cfg['id'] / name)
    root.mkdir(parents=True, exist_ok=True)
    if (root / 'status.json').exists():
        raise RuntimeError('Run retained; use a new run identifier')
    report = dict(status='RUNNING', action=args.action, workload=args.workload,
        **metadata(cfg), circuits={}, observations=[],
        negative_cases=[], blockchain='NOT RUN', started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    save(root / 'status.json', report)
    try:
        if args.action != 'compile':
            if args.workload == 'fixed':
                from src.workloads import load as load_workload
                data = load_workload(cfg)
                provenance = load(ROOT / 'data' / cfg['id'] / 'provenance.json')
                path = ROOT / 'data' / cfg['id'] / provenance['default_file']
                report['workload_provenance'] = dict(path=rel(path), sha256=sha(path),
                    numerical_origin=data['numerical_origin'], candidate_origin=data['candidate_origin'],
                    historical_experiment_fixture_status=data['historical_experiment_fixture_status'],
                    classification='NON_CONFIDENTIAL_SYNTHETIC_TEST_DATA')
            else:
                report['workload_provenance'] = dict(numerical_origin='NEW_EXPLICIT_GENERATION',
                    seed=cfg['seed'], classification='NON_CONFIDENTIAL_SYNTHETIC_TEST_DATA')
        stages = ['a', 'b'] if args.stage == 'both' else [args.stage]
        fixture = None
        for stage in stages:
            try:
                compiled = compile_stage(cfg, stage)
                report['circuits'][stage] = compiled
                if args.action != 'compile':
                    fixture = fixture or fixtures.prepare(cfg, root, 'A_0', workload=args.workload)
                    wit, cost, check = witness(cfg, stage, fixture, compiled, root, stage + '_validation')
                    wit.unlink()
                    report.setdefault('witnesses', {})[stage] = dict(status='PASS', witness=cost, r1cs_check=check,
                        independent_reference='PASS')
                    report['negative_cases'] += negatives(cfg, stage, fixture, compiled, root)
            except ResourceBlocked as error:
                report['circuits'][stage] = dict(status='RESOURCE BLOCKED', reason=str(error),
                    capacity=capacity(cfg, 'compile', stage))
        if args.action in ['demo', 'benchmark']:
            if any(report['circuits'][s]['status'] != 'PASS' for s in ['a', 'b']):
                raise ResourceBlocked('Required circuit compilation is resource blocked')
            keys = {stage: setup_stage(cfg, stage, report['circuits'][stage], args.ptau) for stage in ['a', 'b']}
            report['setup'] = keys
            a_trials = args.a_trials if args.action == 'benchmark' else 1
            b_trials = args.b_trials if args.action == 'benchmark' else args.explanations
            pairs = []
            selected = None
            base = None
            for index in range(a_trials):
                current = fixtures.prepare(cfg, root, 'A_' + str(index), workload=args.workload)
                proof = prove(cfg, 'a', current, report['circuits']['a'], keys['a'], root, index)
                report['observations'].append(proof)
                if index == 0:
                    selected, base = proof, current
            for index in range(b_trials):
                current = fixtures.explanation(cfg, base, index, root, explanation_id='B_' + str(index))
                proof = prove(cfg, 'b', current, report['circuits']['b'], keys['b'], root, index)
                report['observations'].append(proof)
                pairs.append(dict(stageA=dict(proof=selected['proof_path'], public=selected['public_path']),
                                  stageB=dict(proof=proof['proof_path'], public=proof['public_path'])))
                if index == 0:
                    report['negative_cases'] += negatives(cfg, 'b', current, report['circuits']['b'], root, proof, keys['b'])
            report['negative_cases'] += negatives(cfg, 'a', base, report['circuits']['a'], root, selected, keys['a'])
            context = base['public_context']
            manifest = dict(mode='synthetic_stress', configuration=cfg, runRoot=rel(root),
                modelArtifactKeccak=context['modelArtifactKeccak'], schemaManifestKeccak=context['schemaManifestKeccak'],
                policyManifest=fixtures.policy_manifest(cfg), pairs=pairs,
                verifiers=dict(stageA=keys['a']['sol'], stageB=keys['b']['sol']))
            save(root / 'chain_manifest.json', manifest)
            chain_command = ['node', 'src/blockchain/run.ts', '--manifest',
                rel(root / 'chain_manifest.json'), '--output', rel(root / 'blockchain.json')]
            if args.action == 'demo':
                chain_command.append('--smoke')
            _, process = measure('blockchain', chain_command,
                logdir=root / 'logs', timeout=3600)
            report['blockchain'] = load(root / 'blockchain.json')
            report['blockchain_process'] = process
            report['trials'] = dict(stage_a=a_trials, stage_b=b_trials, certified_states=1, warmups=0)
        elif args.prove_b:
            if report['circuits'].get('b', {}).get('status') != 'PASS':
                raise ResourceBlocked('Stage B compilation unavailable')
            key = setup_stage(cfg, 'b', report['circuits']['b'], args.ptau)
            for index in range(args.explanations):
                current = fixtures.explanation(cfg, fixture, index, root,
                    explanation_id='validation_' + str(index))
                proof = prove(cfg, 'b', current, report['circuits']['b'], key, root, index)
                report['observations'].append(proof)
                if index == 0:
                    report['negative_cases'] += negatives(cfg, 'b', current,
                        report['circuits']['b'], root, proof, key)
        report['status'] = 'RESOURCE BLOCKED' if any(v['status'] != 'PASS' for v in report['circuits'].values()) else 'PASS'
    except ResourceBlocked as error:
        report.update(status='RESOURCE BLOCKED', reason=str(error))
    except BaseException as error:
        report.update(status='FAIL', error_type=type(error).__name__, reason=str(error))
        raise
    finally:
        report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        save(root / 'status.json', report)
        save(root / 'measurements.json', report)
        rows_csv(root / 'measurements.csv', report['observations'])
    print(json.dumps(dict(status=report['status'], report=rel(root / 'measurements.json'),
                         counts=dict(proofs=len(report['observations']), negatives=len(report['negative_cases'])))))
    return 0 if report['status'] == 'PASS' else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['compile', 'validate', 'demo', 'benchmark'])
    parser.add_argument('--config', choices=['s1', 's2', 's3'], required=True)
    parser.add_argument('--stage', choices=['a', 'b', 'both'], default='both')
    parser.add_argument('--run-id')
    parser.add_argument('--ptau', help='Prepared setup path inside this directory')
    parser.add_argument('--prove-b', action='store_true', help='Include B proofs in witness validation')
    parser.add_argument('--workload', choices=['fixed', 'generated'], default='fixed',
                        help='Load the provided dataset (default) or explicitly generate numerical data')
    parser.add_argument('--explanations', type=int, default=2)
    parser.add_argument('--a-trials', type=int, default=3)
    parser.add_argument('--b-trials', type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.a_trials <= 1000 or not 2 <= args.b_trials <= 20 or not 2 <= args.explanations <= 20:
        parser.error('Use 1..1000 A trials and 2..20 B explanations')
    if args.action in ['demo', 'benchmark'] and args.stage != 'both':
        parser.error('A demonstration or benchmark requires both stages')
    raise SystemExit(run(args))


if __name__ == '__main__':
    main()
