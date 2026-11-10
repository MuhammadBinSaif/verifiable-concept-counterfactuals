"""Synthetic witnesses with private, resumable commitment randomness."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from eth_hash.auto import keccak
from src.config import MODE, ROOT, validate_config
from src.reference import A_SIGNALS, FIELD, vector
from src.workloads import candidate, numerical as prepare_model


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def contained(path):
    path=Path(path).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError('Fixture output escapes the repository')
    return path


def save_private(path,value):
    path=contained(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    path.parent.chmod(0o700)
    temp=path.with_name(path.name+'.tmp')
    if temp.is_symlink():
        raise ValueError('Private temporary output is a symlink')
    with temp.open('w') as stream:
        temp.chmod(0o600)
        stream.write(canonical(value).decode())
    temp.replace(path)


def load_private(path):
    path=contained(path)
    if path.stat().st_mode & 0o077:
        raise RuntimeError('Private fixture permissions are too broad')
    return json.loads(path.read_text())


def nonce():
    return secrets.randbelow(FIELD-1)+1


def exact_field(value,nonzero=False):
    if type(value) is int:
        n=value
    elif type(value) is str and value.isascii() and value.isdecimal() and str(int(value))==value:
        n=int(value)
    else:
        raise ValueError('Exact canonical field integer required')
    if not (1 if nonzero else 0)<=n<FIELD:
        raise ValueError('Field integer out of range')
    return n


def request(vector_kind,payload,domain=None):
    result=dict(kind=vector_kind,payload=[str(int(v)%FIELD) for v in payload],expectedLength=len(payload))
    if domain is not None:
        result['domain']=domain
    return result


def commit(vectors):
    completed=subprocess.run([os.environ.get('NODE','node'),str(ROOT/'src/commitments/commitments.mjs')],cwd=ROOT,
        input=canonical(dict(op='commitments',vectors=vectors)),capture_output=True,check=False)
    if completed.returncode:
        raise RuntimeError('Commitment bridge failed; private payload suppressed')
    result=json.loads(completed.stdout)
    if len(result.get('commitments',[]))!=len(vectors):
        raise RuntimeError('Commitment bridge result count differs')
    return result['commitments']


def vectors(cfg,parameters,inputs,blinds):
    versions=cfg['versions']
    prefix=[versions[k] for k in ['modelVersion','architectureVersion','schemaVersion','quantizationVersion']]
    head=parameters[-(2*cfg['C']+2):]
    model_payload=prefix+[blinds['modelBlind']]+parameters
    model=request('model',model_payload)
    return [model,request('sequence',prefix+[blinds['headBlind']]+head,1002),
        request('sequence',[versions['modelVersion'],versions['preprocessingVersion'],blinds['inputNonce']]+inputs,1003)]


def state_vector(cfg,context,trace,state_nonce):
    names=['stateCircuitVersion','explanationCircuitVersion','modelCommitmentVersion','modelVersion',
        'architectureVersion','schemaVersion','quantizationVersion','preprocessingVersion']
    payload=[cfg['versions'][k] for k in names]+[context[k] for k in ['C_model_v2','C_head','C_input','originalPrediction']]
    payload += [state_nonce]+trace['conceptsQ']+trace['deltaWQ']+[trace['deltaBQ']]
    if len(payload)!=14+2*cfg['C']:
        raise ValueError('State payload dimension differs')
    return request('sequence',payload,1004)


def explanation_vector(cfg,context,changed,explanation_nonce):
    changed=vector(changed,cfg['C'])
    private_nonce=exact_field(explanation_nonce,nonzero=True)
    if any(context.get(k)!=v for k,v in cfg['versions'].items()):
        raise ValueError('Explanation context does not match exact relation versions')
    payload=[1,cfg['versions']['explanationCircuitVersion'],cfg['versions']['stateCircuitVersion'],
        cfg['versions']['modelVersion'],exact_field(context['C_state_v3']),private_nonce]+changed
    return request('sequence',payload,1007)


def commit_explanation(cfg,context,changed,explanation_nonce):
    return commit([explanation_vector(cfg,context,changed,explanation_nonce)])[0]


def metadata_hash(value):
    return '0x'+keccak(canonical(value)).hex()


def policy_manifest(cfg):
    """Exact dimension-adjusted approved policy, canonically hashed with relation versions."""
    policy=dict(allowedMask=[1]*cfg['C'],conceptDimensions=cfg['C'],conceptMaximum=10000,
        conceptMinimum=0,counterfactualPrediction=0,direction='nonnegative',
        explanationCircuitVersion=cfg['versions']['explanationCircuitVersion'],
        explanationCommitmentDomain=1007,explanationCommitmentVersion=1,l1Bound=4000,
        originalPrediction=1,policyVersion=2,sparsityBound=1,
        stateCircuitVersion=cfg['versions']['stateCircuitVersion'])
    return dict(mode=MODE,policy=policy,canonicalUtf8=canonical(policy).decode(),keccak256=metadata_hash(policy))


def private_randomness(run_root):
    root=contained(Path(run_root)/'private');root.mkdir(parents=True,exist_ok=True,mode=0o700);root.chmod(0o700)
    path=root/'blinding.json'
    if not path.exists() and any((root/'fixtures').rglob('*.json')):
        raise RuntimeError('Private blinding file missing; cannot resume different commitments')
    if not path.exists():
        save_private(path,dict(mode=MODE,modelBlind=nonce(),headBlind=nonce()))
    result=load_private(path)
    if result.get('mode')!=MODE:
        raise RuntimeError('Private randomness mode changed')
    for key in ['modelBlind','headBlind']:
        exact_field(result[key],nonzero=True)
    return result


def _validate_existing(cfg,run_root,fixture):
    selection=fixture.get('workload')
    parameters,inputs,trace=prepare_model(cfg,selection)
    blinds=private_randomness(run_root)
    if (fixture.get('mode')!=MODE or fixture.get('configuration')!=cfg['id'] or fixture.get('seed')!=cfg['seed']
        or canonical(fixture['a']['parametersQ'])!=canonical(parameters) or canonical(fixture['a']['xQ'])!=canonical(inputs) or canonical(fixture['trace'])!=canonical(trace)
        or any(fixture['a'].get(k)!=v for k,v in blinds.items() if k!='mode')
        or any(fixture['public_context'].get(k)!=v for k,v in cfg['versions'].items())):
        raise RuntimeError('Stale fixture/model/versions')
    expected_changed,expected_cf=candidate(cfg,trace,fixture['candidate_index'],selection)
    if fixture['b']['cPrimeQ']!=expected_changed or fixture['counterfactual']!=expected_cf:
        raise RuntimeError('Changed private candidate checkpoint')
    if (canonical(fixture['b']['allowedMask'])!=canonical([1]*cfg['C']) or fixture['b']['sparsityBound']!=1
        or fixture['b']['l1Bound']!=4000 or fixture['b']['originalPrediction']!=1
        or fixture['b']['counterfactualPrediction']!=0):
        raise RuntimeError('Changed authorized policy checkpoint')
    values=commit(vectors(cfg,parameters,inputs,fixture['a']))
    for key,value in zip(['C_model_v2','C_head','C_input'],values,strict=True):
        if fixture['public_context'][key]!=value or fixture['a'][key]!=value or fixture['b'][key]!=value:
            raise RuntimeError('Changed authenticated model/input/head checkpoint')
    expected_state=commit([state_vector(cfg,fixture['public_context'],trace,fixture['a']['stateNonce'])])[0]
    if fixture['public_context']['C_state_v3']!=expected_state or fixture['a']['C_state_v3']!=expected_state or fixture['b']['C_state_v3']!=expected_state:
        raise RuntimeError('Changed state checkpoint')
    context=fixture['public_context']
    for name in A_SIGNALS:
        if fixture['a'][name]!=context[name] or fixture['b'][name]!=context[name]:
            raise RuntimeError('Changed stage public context checkpoint')
    if (fixture['b']['cQ']!=trace['conceptsQ'] or fixture['a']['deltaWQ']!=trace['deltaWQ']
        or fixture['b']['deltaWQ']!=trace['deltaWQ'] or fixture['a']['deltaBQ']!=trace['deltaBQ']
        or fixture['b']['deltaBQ']!=trace['deltaBQ'] or fixture['b']['stateNonce']!=fixture['a']['stateNonce']
        or fixture['b']['explanationCircuitVersion']!=cfg['versions']['explanationCircuitVersion']):
        raise RuntimeError('Changed authenticated head/state witness checkpoint')
    expected=commit_explanation(cfg,fixture['public_context'],expected_changed,fixture['b']['explanationNonce'])
    if fixture['b']['C_explanation']!=expected or fixture['public_context']['C_explanation']!=expected:
        raise RuntimeError('Changed explanation commitment checkpoint')
    opening=load_private(ROOT/fixture['opening_path'])
    if not verify_explanation_opening(cfg,opening,expected,expected_state):
        raise RuntimeError('Changed persisted recipient opening')
    return fixture


def prepare(cfg,run_root,request_index='A_0',candidate_index=0,explanation_id=None,workload='fixed'):
    validate_config(cfg)
    if type(candidate_index) is not int or not 0<=candidate_index<20:
        raise ValueError('Candidate index must be 0..19')
    run_root=contained(run_root)
    label=str(request_index)
    if not label or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in label):
        raise ValueError('Unsafe request index')
    path=run_root/'private/fixtures'/label/f'{candidate_index}.json'
    if path.exists():
        existing=load_private(path)
        if existing.get('workload') != workload:
            raise RuntimeError('Existing fixture belongs to a different workload selection')
        return _validate_existing(cfg,run_root,existing)
    parameters,inputs,trace=prepare_model(cfg,workload)
    blinds={**private_randomness(run_root), 'inputNonce':nonce(), 'stateNonce':nonce()}
    began=time.perf_counter()
    model,head,inp=commit(vectors(cfg,parameters,inputs,blinds))
    first=time.perf_counter()-began
    context={**cfg['versions'],'C_model_v2':model,'C_head':head,'C_input':inp,
        'originalPrediction':trace['prediction']}
    began=time.perf_counter()
    state=commit([state_vector(cfg,context,trace,blinds['stateNonce'])])[0]
    second=time.perf_counter()-began
    context.update(C_state_v3=state,counterfactualPrediction=0,allowedMask=[1]*cfg['C'],sparsityBound=1,l1Bound=4000)
    context.update(modelArtifactKeccak=metadata_hash(dict(mode=MODE,architecture=cfg['architecture'],parametersQ=parameters)),
        schemaManifestKeccak=metadata_hash(dict(mode=MODE,architecture=cfg['architecture'],schemaVersion=cfg['versions']['schemaVersion'])),
        policyManifestKeccak=policy_manifest(cfg)['keccak256'])
    a={name:context[name] for name in A_SIGNALS}
    a.update(parametersQ=parameters,xQ=inputs,inputNonce=blinds['inputNonce'],modelBlind=blinds['modelBlind'],
        headBlind=blinds['headBlind'],stateNonce=blinds['stateNonce'],deltaWQ=trace['deltaWQ'],deltaBQ=trace['deltaBQ'])
    changed,cf=candidate(cfg,trace,candidate_index,workload)
    b={name:context[name] for name in A_SIGNALS}
    b.update(explanationCircuitVersion=cfg['versions']['explanationCircuitVersion'],counterfactualPrediction=0,
        allowedMask=[1]*cfg['C'],sparsityBound=1,l1Bound=4000,cQ=trace['conceptsQ'],stateNonce=blinds['stateNonce'],
        cPrimeQ=changed,deltaWQ=trace['deltaWQ'],deltaBQ=trace['deltaBQ'])
    fixture=dict(mode=MODE,configuration=cfg['id'],seed=cfg['seed'],request_index=label,workload=workload,
        candidate_index=candidate_index,a=a,b=b,trace=trace,counterfactual=cf,public_context=context,
        commitment_seconds=dict(model_head_input=first,state=second))
    fixture=explanation(cfg,fixture,candidate_index,run_root,
        explanation_id=explanation_id if explanation_id is not None else f'fixture_{label}_{candidate_index}')
    save_private(path,fixture)
    return fixture


def explanation(cfg,base,index,run_root,explanation_id=None):
    validate_config(cfg)
    run_root=contained(run_root)
    f=copy.deepcopy(base)
    changed,cf=candidate(cfg,f['trace'],index,f['workload'])
    context=f['public_context']
    identity=dict(configuration=cfg['id'],state=context['C_state_v3'],model=context['modelVersion'],candidate=index,
        explanation_id=str(index) if explanation_id is None else str(explanation_id))
    path=run_root/'private/explanations'/(hashlib.sha256(canonical(identity)).hexdigest()+'.json')
    expected=dict(mode=MODE,configuration=cfg['id'],explanationCommitmentVersion=1,
        **cfg['versions'],C_state_v3=context['C_state_v3'],cPrimeQ=changed)
    if path.exists():
        opening=load_private(path)
        if {k:opening.get(k) for k in expected}!=expected:
            raise RuntimeError('Explanation opening checkpoint changed')
        private_nonce=exact_field(opening['explanationNonce'],nonzero=True)
    else:
        private_nonce=nonce();opening={**expected,'explanationNonce':private_nonce};save_private(path,opening)
    began=time.perf_counter();commitment=commit_explanation(cfg,context,changed,private_nonce);elapsed=time.perf_counter()-began
    f['b'].update(cPrimeQ=changed,explanationNonce=private_nonce,C_explanation=commitment)
    f['public_context']['C_explanation']=commitment
    f['counterfactual']=cf;f['candidate_index']=index;f['opening_path']=str(path.relative_to(ROOT))
    f['commitment_seconds']['explanation']=elapsed
    return f


def verify_explanation_opening(cfg,opening,expected_commitment,expected_state,expected_model=1):
    try:
        if opening.get('mode')!=MODE or opening.get('configuration')!=cfg['id'] or type(opening.get('explanationCommitmentVersion')) is not int or opening['explanationCommitmentVersion']!=1:
            return False
        if exact_field(opening['C_state_v3'])!=exact_field(expected_state) or exact_field(opening['modelVersion'])!=expected_model:
            return False
        actual=commit_explanation(cfg,opening,opening['cPrimeQ'],opening['explanationNonce'])
        return actual==str(exact_field(expected_commitment))
    except (ValueError,TypeError,KeyError):
        return False
