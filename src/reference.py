"""Exact integer inference and deterministic synthetic model generation."""
from __future__ import annotations
import hashlib
from src.config import validate_config

SCALE = 10000
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
A_SIGNALS = ('modelVersion', 'architectureVersion', 'schemaVersion',
    'quantizationVersion', 'preprocessingVersion', 'C_model_v2', 'C_head',
    'C_input', 'C_state_v3', 'originalPrediction', 'stateCircuitVersion', 'modelCommitmentVersion')


def b_signals(cfg):
    return A_SIGNALS + ('explanationCircuitVersion', 'counterfactualPrediction') + tuple(
        f'allowedMask[{i}]' for i in range(cfg['C'])) + ('sparsityBound', 'l1Bound', 'C_explanation')


def round_ratio(numerator, denominator=SCALE):
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError('Exact integer ratio required')
    value, remainder = divmod(abs(numerator), denominator)
    value += 2 * remainder >= denominator
    return -value if numerator < 0 else value


def vector(values, length, maximum=SCALE):
    if type(values) is not list or len(values) != length or any(type(v) is not int or not 0 <= v <= maximum for v in values):
        raise ValueError('Exact vector dimensions and range required')
    return values


def tensors(cfg):
    d, h1, h2, c = (cfg[k] for k in ('D', 'H1', 'H2', 'C'))
    result = [('W1', (h1, d), h1*d, 33421), ('b1', (h1,), h1, 7034)]
    if h2:
        result += [('W2', (h2, h1), h1*h2, 20465), ('b2', (h2,), h2, 10066)]
    n = h2 or h1
    return result + [('W3', (c, n), c*n, 20465), ('b3', (c,), c, 10066),
        ('Whead', (2, c), 2*c, 25157), ('bhead', (2,), 2, 4927)]


def validate_parameters(cfg, parameters):
    if type(parameters) is not list or len(parameters) != cfg['parameters']:
        raise ValueError('Exact canonically ordered parameter count required')
    cursor = 0
    for _, _, count, bound in tensors(cfg):
        if any(type(v) is not int or abs(v) > bound for v in parameters[cursor:cursor+count]):
            raise ValueError('Parameter exceeds approved per-value bound')
        cursor += count
    if cursor != cfg['parameters']:
        raise ValueError('Tensor layout does not match configuration')
    return parameters


def unpack(cfg, parameters):
    p = validate_parameters(cfg, parameters)
    values = {}; cursor = 0
    for name, _, count, _ in tensors(cfg):
        values[name] = p[cursor:cursor+count]; cursor += count
    return values


def affine(inputs, weights, biases):
    n = len(inputs)
    return [round_ratio(sum(inputs[i]*weights[j*n+i] for i in range(n)) + bias*SCALE)
            for j, bias in enumerate(biases)]


def infer(cfg, parameters, inputs):
    values = unpack(cfg, parameters)
    x = vector(inputs, cfg['D'])
    first = affine(x, values['W1'], values['b1'])
    h1 = [max(0, v) for v in first]
    second = affine(h1, values['W2'], values['b2']) if cfg['H2'] else []
    h2 = [max(0, v) for v in second]
    third = affine(h2 or h1, values['W3'], values['b3'])
    concepts = [min(SCALE, max(0, round_ratio(v + 3*SCALE, 6))) for v in third]
    c = cfg['C']; head = values['Whead']; biases = values['bhead']
    dw = [head[i]-head[c+i] for i in range(c)]
    db = biases[0]-biases[1]
    scores = [sum(concepts[i]*head[j*c+i] for i in range(c)) + biases[j]*SCALE for j in range(2)]
    margin = db*SCALE + sum(a*b for a,b in zip(concepts,dw,strict=True))
    if margin != scores[0]-scores[1]:
        raise RuntimeError('Class scores and differential head differ')
    return dict(firstPreactivationQ=first, hidden1Q=h1, secondPreactivationQ=second,
        hidden2Q=h2, encoderPreactivationQ=third, conceptsQ=concepts,
        deltaWQ=dw, deltaBQ=db, marginQ=margin, prediction=int(margin < 0),
        scoreNumeratorsQ=scores)


def sample(seed, domain, index, lower, upper):
    value = int.from_bytes(hashlib.sha256(f'stress-v1:{seed}:{domain}:{index}'.encode()).digest(), 'big')
    return lower + value % (upper-lower+1)


def prepare(cfg):
    validate_config(cfg)
    d, h1, h2, c, seed = (cfg[k] for k in ('D','H1','H2','C','seed'))
    p = [sample(seed,'w1',i,1,9) for i in range(d*h1)]
    p += [sample(seed,'b1',i,600,1200) for i in range(h1)]
    if h2:
        p += [sample(seed,'w2',i,1,30)*(-1 if sample(seed,'w2s',i,0,1) else 1) for i in range(h1*h2)]
        p += [sample(seed,'b2',i,500,1000) for i in range(h2)]
    p += [sample(seed,'w3',i,1,50)*(-1 if sample(seed,'w3s',i,0,1) else 1) for i in range((h2 or h1)*c)]
    p += [sample(seed,'b3',i,-100,100) for i in range(c)]
    p += [10000]+[sample(seed,'head0',i,2,11) for i in range(1,c)]
    p += [1]+[sample(seed,'head1',i,12,21) for i in range(1,c)]+[-3000,3000]
    x = [sample(seed,'input',i,800,1200) for i in range(d)]
    trace = infer(cfg,p,x)
    if trace['prediction'] != 1 or not all(trace['hidden1Q']) or (h2 and not all(trace['hidden2Q'])):
        raise RuntimeError('Seed does not provide the required connected original fixture')
    for index in range(20):
        candidate(cfg,trace,index)
    return p,x,trace


def validate_candidate(cfg, trace, changed, allowed=None, sparsity=1, l1=4000):
    original = vector(trace['conceptsQ'],cfg['C'])
    changed = vector(changed,cfg['C'])
    allowed = [1]*cfg['C'] if allowed is None else allowed
    if (allowed != [1]*cfg['C'] or any(type(v) is not int for v in allowed)
        or type(sparsity) is not int or sparsity != 1 or type(l1) is not int or l1 != 4000):
        raise ValueError('Unsupported fixed intervention policy')
    delta = [b-a for a,b in zip(original,changed,strict=True)]
    if min(delta)<0 or sum(v != 0 for v in delta)>sparsity or sum(delta)>l1:
        raise ValueError('Forbidden intervention')
    margin = trace['deltaBQ']*SCALE + sum(a*b for a,b in zip(changed,trace['deltaWQ'],strict=True))
    if trace['prediction'] != 1 or margin<0:
        raise ValueError('DEFAULT to NON-DEFAULT prediction change required')
    return dict(marginQ=margin,prediction=0,L0=sum(v != 0 for v in delta),L1Q=sum(delta))


def candidate(cfg,trace,index):
    if type(index) is not int or not 0<=index<20:
        raise ValueError('Candidate index must be 0..19')
    changed = list(trace['conceptsQ']); changed[0] += 2000+index
    return changed,validate_candidate(cfg,trace,changed)


def public_signals(cfg,stage,context):
    if stage not in {'a','b'}:
        raise ValueError('Unsupported proof stage')
    result=[]
    for name in A_SIGNALS if stage=='a' else b_signals(cfg):
        value=context['allowedMask'][int(name[12:-1])] if name.startswith('allowedMask[') else context[name]
        if type(value) is int:
            n=value
        elif type(value) is str and value.isascii() and value.isdecimal() and str(int(value))==value:
            n=int(value)
        else:
            raise ValueError('Public signal must be an exact canonical field integer')
        if not 0<=n<FIELD:
            raise ValueError('Public signal outside scalar field')
        result.append(str(n))
    return result
