/** Local proof verification and certified-state reuse. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, realpathSync, existsSync, lstatSync } from "node:fs";
import { dirname, resolve, relative, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BaseError, ContractFunctionRevertedError, encodeAbiParameters, encodeFunctionData, keccak256, toBytes, toHex, type Abi, type Address, type Hex } from "viem";
import { normalizeProof, SCALAR_FIELD, type Groth16Proof } from "./protocol.ts";

const ROOT = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
export type Configuration = {id:string;variant:"optimized";strategy:"reuse";D:number;H1:number;H2:number;C:number;architectureVersion:number;schemaVersion:number;stateCircuitVersion:number;explanationCircuitVersion:number;modelCommitmentVersion:number;modelVersion:number;quantizationVersion:number;preprocessingVersion:number};
const MATRIX = {
 s1:[19,16,0,4,201,202,2,"optimized","reuse"],
 s2:[64,32,16,8,301,302,2,"optimized","reuse"],
 s3:[200,64,32,16,101,102,2,"optimized","reuse"],
} as const;
function exactInteger(value:unknown):number {
 assert.ok(typeof value==="number"&&Number.isSafeInteger(value),"Exact integer configuration required");return value;
}
export function normalizeConfiguration(raw:unknown):Configuration {
 assert.ok(raw&&typeof raw==="object"&&!Array.isArray(raw));
 const outer=raw as Record<string,any>, value={...(outer.versions??{}),...outer};
 const expected=MATRIX[value.id as keyof typeof MATRIX];assert.ok(expected,"Only S1, S2 and S3 configurations are supported");
 const [D,H1,H2,C,arch,relation,commitment,variant,strategy]=expected;
 const shape=value.architecture??[value.D,value.H1,...(value.H2?[value.H2]:[]),value.C,2];
 assert.deepEqual(shape,H2?[D,H1,H2,C,2]:[D,H1,C,2],"Architecture does not match configuration identity");
 for(const [name,want] of Object.entries({D,H1,H2,C,architectureVersion:arch,schemaVersion:arch,stateCircuitVersion:relation,explanationCircuitVersion:relation,modelCommitmentVersion:commitment,modelVersion:1,quantizationVersion:1,preprocessingVersion:1})){
  const actual=["D","H1","H2","C"].includes(name)?value[name]??({D,H1,H2,C} as any)[name]:value[name];
  assert.equal(exactInteger(actual),want,"Unsupported fixed version/shape: "+name);
 }
 if(value.policy!==undefined)assert.deepEqual(value.policy,{allowed_mask:Array(C).fill(1),sparsity_bound:1,l1_bound:4000,concept_minimum:0,concept_maximum:10000,direction:'nonnegative'},'Exact fixed policy required');
 if(value.variant!==undefined)assert.equal(value.variant,variant);if(value.strategy!==undefined)assert.equal(value.strategy,strategy);
 return {id:value.id,variant,strategy,D,H1,H2,C,architectureVersion:arch,schemaVersion:arch,stateCircuitVersion:relation,explanationCircuitVersion:relation,modelCommitmentVersion:commitment,modelVersion:1,quantizationVersion:1,preprocessingVersion:1};
}
export function canonical(value:unknown):string {
 if(value===null||typeof value==="boolean"||typeof value==="string")return JSON.stringify(value);
 if(typeof value==="number"){assert.ok(Number.isSafeInteger(value));return JSON.stringify(value);}
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 assert.ok(value&&typeof value==="object");const object=value as Record<string,unknown>;
 return '{'+Object.keys(object).sort().map(key=>JSON.stringify(key)+':'+canonical(object[key])).join(',')+'}';
}
export function policyManifest(input:unknown):{mode:string;policy:Record<string,unknown>;canonicalUtf8:string;keccak256:Hex} {
 const c=normalizeConfiguration(input),policy={allowedMask:Array(c.C).fill(1),conceptDimensions:c.C,conceptMaximum:10000,conceptMinimum:0,counterfactualPrediction:0,direction:"nonnegative",explanationCircuitVersion:c.explanationCircuitVersion,explanationCommitmentDomain:1007,explanationCommitmentVersion:1,l1Bound:4000,originalPrediction:1,policyVersion:2,sparsityBound:1,stateCircuitVersion:c.stateCircuitVersion};
 const canonicalUtf8=canonical(policy);return {mode:"synthetic_stress",policy,canonicalUtf8,keccak256:keccak256(toBytes(canonicalUtf8))};
}
export function validatePolicyManifest(input:unknown, value:unknown):Hex {
 assert.deepEqual(value,policyManifest(input),"Structured policy/canonical bytes/digest must match the exact configuration policy");return policyManifest(input).keccak256;
}
export function policyHash(input:unknown):Hex{return policyManifest(input).keccak256;}
function containedFile(path:string):string {
 const actual=realpathSync(resolve(ROOT,path)),r=relative(ROOT,actual);assert.ok(r&&!r.startsWith('..')&&!isAbsolute(r),"Input must stay inside repository");return actual;
}
function containedOutput(path:string):string {
 const actual=resolve(ROOT,path),r=relative(ROOT,actual);assert.ok(r&&!r.startsWith('..')&&!isAbsolute(r),"Output must stay inside the release directory");
 let ancestor=dirname(actual);while(!existsSync(ancestor))ancestor=dirname(ancestor);
 const real=realpathSync(ancestor),a=relative(ROOT,real);assert.ok(a===''||(!a.startsWith('..')&&!isAbsolute(a)),"Output ancestor escapes the release directory");
 assert.ok(!lstatSync(actual,{throwIfNoEntry:false})?.isSymbolicLink(),"Refusing symlink output");
 if(existsSync(actual))assert.equal(realpathSync(actual),actual,"Refusing symlink output");return actual;
}
const PROTOCOL_NAMES=["ModelRegistryV3","InputCommitmentRegistryV3","StateCertificationRegistryV3","ExplanationCertificateRegistryV3"];
export function adaptProtocolSources(input:unknown):Record<string,{content:string}> {
 const c=normalizeConfiguration(input),result:Record<string,{content:string}>={};
 for(const name of PROTOCOL_NAMES){
  let source=readFileSync(join(ROOT,'contracts/protocol',name+'.sol'),'utf8');
  if(name==='ModelRegistryV3'){
   for(const [field,old,next] of [['architectureVersion',101,c.architectureVersion],['schemaVersion',101,c.schemaVersion],['stateCircuitVersion',102,c.stateCircuitVersion],['explanationCircuitVersion',102,c.explanationCircuitVersion],['modelCommitmentVersion',2,c.modelCommitmentVersion]] as const){
    const token=`registration.${field} != ${old}`;assert.ok(source.includes(token));source=source.replaceAll(token,`registration.${field} != ${next}`);
   }
  }
  if(name==='StateCertificationRegistryV3'){
   source=source.replace('STATE_CIRCUIT_VERSION = 102;',`STATE_CIRCUIT_VERSION = ${c.stateCircuitVersion};`);
   source=source.replace('publicSignals[MODEL_COMMITMENT_VERSION_INDEX], 2)','publicSignals[MODEL_COMMITMENT_VERSION_INDEX], '+c.modelCommitmentVersion+')');
  }
  if(name==='ExplanationCertificateRegistryV3'){
   source=source.replace(/0x8af45e12dcf7ee3f1fac51a16c08223cc83e4f776b21ae5f769973357fe724c5/g,policyHash(c));
   source=source.replace('EXPLANATION_CIRCUIT_VERSION = 102;',`EXPLANATION_CIRCUIT_VERSION = ${c.explanationCircuitVersion};`);
   for(let index=c.C;index<16;index++){
    source=source.replace(new RegExp(`^    uint256 public constant ALLOWED_MASK_${index}_INDEX = \\d+;\\n`,'m'),'');
    source=source.replace(new RegExp(`^        _match\\(ALLOWED_MASK_${index}_INDEX, publicSignals\\[ALLOWED_MASK_${index}_INDEX\\], 1\\);\\n`,'m'),'');
   }
   source=source.replace('SPARSITY_BOUND_INDEX = 30;',`SPARSITY_BOUND_INDEX = ${14+c.C};`).replace('L1_BOUND_INDEX = 31;',`L1_BOUND_INDEX = ${15+c.C};`).replace('EXPLANATION_COMMITMENT_INDEX = 32;',`EXPLANATION_COMMITMENT_INDEX = ${16+c.C};`);
   source=source.replaceAll('uint256[33]',`uint256[${17+c.C}]`).replace('i < 33;',`i < ${17+c.C};`);
   source=source.replace('publicSignals[STATE_CIRCUIT_VERSION_INDEX], 102)',`publicSignals[STATE_CIRCUIT_VERSION_INDEX], ${c.stateCircuitVersion})`);
   source=source.replace('publicSignals[EXPLANATION_CIRCUIT_VERSION_INDEX], 102)',`publicSignals[EXPLANATION_CIRCUIT_VERSION_INDEX], ${c.explanationCircuitVersion})`);
   source=source.replace('publicSignals[MODEL_COMMITMENT_VERSION_INDEX], 2)',`publicSignals[MODEL_COMMITMENT_VERSION_INDEX], ${c.modelCommitmentVersion})`);
   source=source.replace('state.stateCircuitVersion != 102',`state.stateCircuitVersion != ${c.stateCircuitVersion}`).replaceAll('state.modelCommitmentVersion != 2',`state.modelCommitmentVersion != ${c.modelCommitmentVersion}`).replaceAll('model.modelCommitmentVersion != 2',`model.modelCommitmentVersion != ${c.modelCommitmentVersion}`);
  }
  result['contracts/protocol/'+name+'.sol']={content:source};
 }
 const iface=readFileSync(join(ROOT,'contracts/interfaces/IVerifiers.sol'),'utf8').replaceAll('uint256[33]',`uint256[${17+c.C}]`);
 result['contracts/interfaces/IVerifiers.sol']={content:iface};return result;
}
function generateContracts(c:Configuration, verifiers:{stageA:string;stageB:string}, target:string):Record<string,unknown> {
 const sources=adaptProtocolSources(c),identities:Record<string,unknown>={};
 for(const [name,{content}] of Object.entries(sources)){
  const p=containedOutput(join(target,name));mkdirSync(dirname(p),{recursive:true});writeFileSync(p,content);
  identities[name]={stagedKeccak256:keccak256(toBytes(content))};
 }
 for(const [stage,name,count] of [["stageA","StateGroth16VerifierV3",12],["stageB","ExplanationGroth16VerifierV3",17+c.C]] as const){
  const input=readFileSync(containedFile(verifiers[stage]),'utf8');
  assert.match(input,new RegExp(`uint(?:256)?\\[${count}\\]\\s+(?:calldata|memory)\\s+_pubSignals`));
  assert.equal((input.match(/contract\s+[A-Za-z_][A-Za-z_0-9]*\s*\{/g)??[]).length,1);assert.match(input,/pairing|staticcall/);assert.match(input,/snarkJS|snarkjs/);
  const source=input.replace(/contract\s+[A-Za-z_][A-Za-z_0-9]*\s*\{/,`contract ${name} {`),p=containedOutput(join(target,'contracts/verifiers',name+'.sol'));
  mkdirSync(dirname(p),{recursive:true});writeFileSync(p,source);identities[name]={inputKeccak256:keccak256(toBytes(input)),stagedKeccak256:keccak256(toBytes(source)),publicSignals:count};
 }
 return {mode:'synthetic_stress',configuration:c,policyManifest:policyManifest(c),sources:identities,source:'In-memory dimension/version adaptation of preserved registries; actual fresh verifier exports required'};
}
export function hardhatConfig(target:string):string {
 const config=containedOutput(join(target,'hardhat.config.ts'));
 const body=`import {defineConfig} from 'hardhat/config';\nimport toolbox from '@nomicfoundation/hardhat-toolbox-viem';\nimport {createRequire} from 'node:module';\nconst require=createRequire(import.meta.url);\nexport default defineConfig({plugins:[toolbox],solidity:{version:'0.8.37',path:require.resolve('solc/soljson.js'),settings:{optimizer:{enabled:true,runs:200},evmVersion:'prague',outputSelection:{'*':{'':['ast'],'*':['abi','evm.bytecode','evm.deployedBytecode','evm.methodIdentifiers','storageLayout']}}}},paths:{sources:${JSON.stringify(join(target,'contracts'))},tests:{nodejs:${JSON.stringify(join(target,'tests'))}},cache:${JSON.stringify(join(target,'cache'))},artifacts:${JSON.stringify(join(target,'hardhat'))}},networks:{hardhatMainnet:{type:'edr-simulated',chainType:'l1',chainId:31337,hardfork:'prague'}}});\n`;
 mkdirSync(dirname(config),{recursive:true});writeFileSync(config,body);return config;
}
type ProofFiles = { proof: string; public: string };
type Manifest = {
  mode: "synthetic_stress";
  configuration: Configuration;
  modelArtifactKeccak: Hex; schemaManifestKeccak: Hex;
  verifierSources?: { stageA: string; stageB: string };
  reuse?: { stageA: ProofFiles; explanations: ProofFiles[] };
};
type ContractName = "ModelRegistryV3" | "InputCommitmentRegistryV3" | "StateGroth16VerifierV3" | "ExplanationGroth16VerifierV3" | "StateCertificationRegistryV3" | "ExplanationCertificateRegistryV3";
const NAMES: ContractName[] = ["ModelRegistryV3", "InputCommitmentRegistryV3", "StateGroth16VerifierV3", "ExplanationGroth16VerifierV3", "StateCertificationRegistryV3", "ExplanationCertificateRegistryV3"];
type Proof = { proof: Groth16Proof; signals: bigint[]; files: ProofFiles };
type StorageMember = { label: string; slot: string; offset: number; type: string };
type StorageType = { encoding: string; label: string; numberOfBytes: string; key?: string; value?: string; members?: StorageMember[] };
type StorageLayout = { storage: StorageMember[]; types: Record<string, StorageType> };
type ObservedSlot = { contract: ContractName; slot: Hex; origin: string };
type Observation = { contract: ContractName; slot: Hex; origin: string; value: Hex };
type Transaction = { strategy: string; phase: "deployment" | "setup" | "primary" | "security"; action: string; candidate: number; transactionHash: Hex; blockNumber: string; gasUsed: string; calldataBytes: number; status: "success"; wallSeconds?:number; storage?: Record<string, unknown> };
type Negative = { name: string; expectedError: string; actualError: string; status: "PASS"; rejected:true; actual_execution:true; layer:"EVM_DECODED_REVERT" };
const proofAbi = { type: "tuple", components: [{ name: "a", type: "uint256[2]" }, { name: "b", type: "uint256[2][2]" }, { name: "c", type: "uint256[2]" }] } as const;
const domains = Object.fromEntries(["REQUEST", "STATE", "CERTIFICATE"].map(n => [n, keccak256(toBytes(`FL-XAI-ZKP-BC:${n}:v3`))])) as Record<string, Hex>;
function json<T>(path: string): T { return JSON.parse(readFileSync(path, "utf8")) as T; }
function serial(value: unknown): string { return JSON.stringify(value, (_k, v) => typeof v === "bigint" ? v.toString() : v, 2) + "\n"; }
function nonce(label: string): Hex { return keccak256(toBytes(`large-model-stress:public-chain-nonce:${label}`)); }
function hashProof(p: Proof): Hex { return keccak256(encodeAbiParameters([proofAbi, { type: `uint256[${p.signals.length}]` }], [p.proof, p.signals])); }
function requestId(input: bigint, n: Hex): Hex { return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }, { type: "bytes32" }], [domains.REQUEST, input, n])); }
function stateId(request: Hex, p: Proof): Hex { return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "uint256" }], [domains.STATE, request, p.signals[0], p.signals[8]])); }
function certificateId(state: Hex, p: Proof, n: Hex): Hex { return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "bytes32" }, { type: "bytes32" }], [domains.CERTIFICATE, state, p.signals[0], hashProof(p), n])); }
function loadProof(files: ProofFiles, count: number, c: Configuration, stage: "A" | "B"): Proof {
  files={proof:containedFile(files.proof),public:containedFile(files.public)};
  const signals = json<unknown[]>(files.public);
  assert.ok(Array.isArray(signals) && signals.length === count, "Exact configuration public-signal length required");
  const parsed = signals.map(value => { assert.ok(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)); const n = BigInt(value); assert.ok(n < SCALAR_FIELD); return n; });
  assert.equal(parsed[0], 1n); assert.equal(parsed[1], BigInt(c.architectureVersion)); assert.equal(parsed[2], BigInt(c.schemaVersion));
  assert.equal(parsed[3], 1n); assert.equal(parsed[4], 1n); assert.equal(parsed[9], 1n);
  assert.equal(parsed[10], BigInt(c.stateCircuitVersion)); assert.equal(parsed[11], BigInt(c.modelCommitmentVersion));
  if (stage === "B") {
    assert.equal(parsed[12], BigInt(c.explanationCircuitVersion)); assert.equal(parsed[13], 0n);
    assert.deepEqual(parsed.slice(14, 14 + c.C), Array(c.C).fill(1n));
    assert.equal(parsed[14 + c.C], 1n); assert.equal(parsed[15 + c.C], 4000n);
    assert.equal(parsed.length,17+c.C); assert.ok(parsed[16+c.C] < SCALAR_FIELD);
  }
  return { proof: normalizeProof(json(files.proof)), signals: parsed, files };
}

async function runStrategy(hre: any, manifest: Manifest, layouts: Record<ContractName, StorageLayout>, requiredPairs:number) {
  const strategy = "reuse";
  const strategyStarted = process.hrtime.bigint();
  const c = manifest.configuration;
  const sourcePairs = manifest.reuse!.explanations.map(stageB => ({ stageA: manifest.reuse!.stageA, stageB }));
  assert.ok(sourcePairs.length > 0);
  const pairs = sourcePairs.map(pair => ({ a: loadProof(pair.stageA, 12, c, "A"), b: loadProof(pair.stageB, 17 + c.C, c, "B") }));
  for (const pair of pairs) assert.deepEqual(pair.a.signals, pair.b.signals.slice(0, 12), "Stage B must authenticate its complete Stage A context");
  assert.equal(pairs.length,requiredPairs,"Exact validated explanation count required");
  assert.equal(new Set(pairs.map(p=>p.b.signals[16+c.C].toString())).size,requiredPairs,"Distinct explanation commitments required");
  const stateSet=new Set(pairs.map(p=>p.a.signals[8].toString()));
  assert.equal(stateSet.size,1,"All explanations must reuse one certified state");
  assert.equal(new Set(pairs.map(p=>createHash('sha256').update(readFileSync(p.a.files.proof)).digest('hex'))).size,1,"Reuse must reference the same A proof");

  const connection = await hre.network.create("hardhatMainnet");
  const client = await connection.viem.getPublicClient(); const wallets = await connection.viem.getWalletClients(); const wallet = wallets[0]; assert.ok(wallet);
  const contracts = {} as Record<ContractName, { address: Address; abi: Abi }>;
  const transactions: Transaction[] = [], negatives: Negative[] = [], known = new Map<string, ObservedSlot>();
  const add = (contract: ContractName, slot: bigint, origin: string) => { const h = toHex(slot, { size: 32 }); known.set(`${contract}:${h}`, { contract, slot: h, origin }); };
  function trackMap(contract: ContractName, label: string, key: Hex | bigint) {
    const layout = layouts[contract]; const member = layout.storage.find(s => s.label === label); assert.ok(member, `Compiler layout missing ${contract}.${label}`);
    const type = layout.types[member.type]; assert.equal(type.encoding, "mapping"); assert.ok(type.value);
    const keyType = layout.types[type.key!]; const valueType = layout.types[type.value];
    const base = BigInt(keccak256(encodeAbiParameters([{ type: keyType.label ?? (typeof key === "bigint" ? "uint256" : "bytes32") } as any, { type: "uint256" }], [key, BigInt(member.slot)])));
    const offsets = valueType.members ? [...new Set(valueType.members.map(m => m.slot))].map(BigInt) : Array.from({ length: Math.ceil(Number(valueType.numberOfBytes) / 32) }, (_, i) => BigInt(i));
    for (const offset of offsets) add(contract, base + offset, `${label}[${key}]+${offset}`);
  }
  async function snapshot(): Promise<Observation[]> {
    const out: Observation[] = [];
    for (const item of known.values()) { const value = await client.getStorageAt({ address: contracts[item.contract].address, slot: item.slot }); out.push({ ...item, value: value ?? toHex(0, { size: 32 }) }); }
    return out;
  }
  async function read(name: ContractName, functionName: string, args: unknown[] = []) { return client.readContract({ ...contracts[name], functionName, args }); }
  async function send(name: ContractName, functionName: string, args: unknown[], action: string, phase: Transaction["phase"], candidate = 0, submitter = wallet) {
    const txStarted = process.hrtime.bigint();
    const before = phase === "primary" ? await snapshot() : undefined;
    const data = encodeFunctionData({ abi: contracts[name].abi, functionName, args });
    const { request } = await client.simulateContract({ ...contracts[name], functionName, args, account: submitter.account });
    const hash = await submitter.writeContract(request); const receipt = await client.waitForTransactionReceipt({ hash }); assert.equal(receipt.status, "success");
    const tx: Transaction = { strategy, phase, action, candidate, transactionHash: hash, blockNumber: receipt.blockNumber.toString(), gasUsed: receipt.gasUsed.toString(), calldataBytes: (data.length - 2) / 2, status: "success" };
    if (before) {
      const after = await snapshot(); const was = new Map(before.map(o => [`${o.contract}:${o.slot}`, o.value]));
      const nonzero = after.filter(o => BigInt(o.value) !== 0n), fresh = nonzero.filter(o => BigInt(was.get(`${o.contract}:${o.slot}`)!) === 0n);
      const changedExisting = after.filter(o => BigInt(was.get(`${o.contract}:${o.slot}`)!) !== 0n && was.get(`${o.contract}:${o.slot}`) !== o.value);
      tx.storage = { method: "eth_getStorageAt using exact solc storageLayout roots and struct member offsets", queriedSlots: after.length, observedNonzeroSlotsAfter: nonzero.length, observedNonzeroBytesAfter: nonzero.length * 32, newlyNonzeroSlots: fresh.length, changedExistingSlots: changedExisting.length, before, after };
    }
    Object.assign(tx,{wallSeconds:Number(process.hrtime.bigint()-txStarted)/1e9});
    transactions.push(tx); return tx;
  }
  async function reject(name: string, contract: ContractName, fn: string, args: unknown[], expected: string, actor = wallet.account) {
    let decoded: string | undefined;
    try { await client.simulateContract({ ...contracts[contract], functionName: fn, args, account: actor }); }
    catch (error) { if (error instanceof BaseError) { const cause = error.walk(c => c instanceof ContractFunctionRevertedError); if (cause instanceof ContractFunctionRevertedError) decoded = cause.data?.errorName; } if (!decoded) throw error; }
    assert.equal(decoded, expected, `${name}: infrastructure failures never count as security rejection`);
    negatives.push({ name, expectedError: expected, actualError: decoded!, status: "PASS", rejected:true, actual_execution:true, layer:"EVM_DECODED_REVERT" });
  }
  try {
    for (const name of NAMES) {
      const args = name === "StateCertificationRegistryV3" ? [contracts.ModelRegistryV3.address, contracts.InputCommitmentRegistryV3.address, contracts.StateGroth16VerifierV3.address]
        : name === "ExplanationCertificateRegistryV3" ? [contracts.ModelRegistryV3.address, contracts.StateCertificationRegistryV3.address, contracts.ExplanationGroth16VerifierV3.address, policyHash(c)] : [];
      const deploymentStarted=process.hrtime.bigint();
      const { contract, deploymentTransaction } = await connection.viem.sendDeploymentTransaction(name, args);
      const receipt = await client.waitForTransactionReceipt({ hash: deploymentTransaction.hash }); assert.equal(receipt.status, "success");
      const artifact = await hre.artifacts.readArtifact(name); contracts[name] = { address: contract.address, abi: artifact.abi };
      transactions.push({ strategy, phase: "deployment", action: `deploy_${name}`, candidate: 0, transactionHash: receipt.transactionHash, blockNumber: receipt.blockNumber.toString(), gasUsed: receipt.gasUsed.toString(), calldataBytes: (deploymentTransaction.input.length - 2) / 2, status: "success", wallSeconds:Number(process.hrtime.bigint()-deploymentStarted)/1e9 });
      for (const field of layouts[name].storage) if (layouts[name].types[field.type].encoding !== "mapping") add(name, BigInt(field.slot), field.label);
    }
    await send("InputCommitmentRegistryV3", "bindStateRegistry", [contracts.StateCertificationRegistryV3.address], "bind_state_registry", "setup");
    const first = pairs[0].a;
    trackMap("ModelRegistryV3", "schemaManifestKeccak", BigInt(c.schemaVersion)); trackMap("ModelRegistryV3", "models", 1n);
    await send("ModelRegistryV3", "registerSchema", [BigInt(c.schemaVersion), manifest.schemaManifestKeccak], "register_schema", "setup");
    const registration = { modelArtifactKeccak: manifest.modelArtifactKeccak, fullModelCommitment: first.signals[5], headCommitment: first.signals[6], schemaVersion: BigInt(c.schemaVersion), architectureVersion: BigInt(c.architectureVersion), quantizationVersion: 1n, preprocessingVersion: 1n, stateCircuitVersion: BigInt(c.stateCircuitVersion), explanationCircuitVersion: BigInt(c.explanationCircuitVersion), modelCommitmentVersion: BigInt(c.modelCommitmentVersion) };
    await send("ModelRegistryV3", "registerModel", [1n, registration], "register_model", "setup");
    const setupStorage = await snapshot(); const certificates: Hex[] = [], stateIds: Hex[] = [], prefixes: Record<string, unknown>[] = [];
    let reusedState: Hex | undefined, reusedRequest: Hex | undefined;
    for (let i = 0; i < pairs.length; i++) {
      const { a, b } = pairs[i]; assert.equal(a.signals[5], first.signals[5]); assert.equal(a.signals[6], first.signals[6]);
      let state: Hex, request: Hex;
      if (i > 0) { state = reusedState!; request = reusedRequest!; }
      else {
        const n = nonce(`${c.id ?? "large_200_64_32_16"}:${strategy}:request:${i}`); request = requestId(a.signals[7], n); state = stateId(request, a);
        trackMap("InputCommitmentRegistryV3", "requests", request);
        await send("InputCommitmentRegistryV3", "registerInputRequest", [a.signals[7], n], "anchor_input", "primary", i);
        assert.equal(await read("StateGroth16VerifierV3", "verifyProof", [a.proof.a, a.proof.b, a.proof.c, a.signals]), true, "Actual Stage A Groth16 verifier control must accept");
        if (i === 0) {
          assert.ok(wallets[1], "Second local account required for role checks");
          await reject("unauthorized_model_registration", "ModelRegistryV3", "registerModel", [2n, registration], "AuthorizationReject", wallets[1].account);
          await reject("unauthorized_request_consumption", "InputCommitmentRegistryV3", "consumeRequest", [request, state], "AuthorizationReject", wallets[1].account);
          await reject("duplicate_input_request", "InputCommitmentRegistryV3", "registerInputRequest", [a.signals[7], n], "DuplicateReject");
          const wrongArch = [...a.signals]; wrongArch[1] += 1n;
          await reject("mismatched_architecture", "StateCertificationRegistryV3", "certifyState", [request, a.proof, wrongArch], "RegistryBindingReject");
          const wrongSchema = [...a.signals]; wrongSchema[2] += 1n;
          await reject("mismatched_schema", "StateCertificationRegistryV3", "certifyState", [request, a.proof, wrongSchema], "RegistryBindingReject");
          const wrongInput = [...a.signals]; wrongInput[7] = (wrongInput[7] + 1n) % SCALAR_FIELD;
          await reject("mismatched_anchored_input", "StateCertificationRegistryV3", "certifyState", [request, a.proof, wrongInput], "RegistryBindingReject");
          await reject("tampered_stage_a_proof", "StateCertificationRegistryV3", "certifyState", [request, { ...a.proof, a: [0n, 0n] }, a.signals], "Groth16VerificationFalse");
          await reject("stale_registration_versions", "ModelRegistryV3", "registerModel", [2n, { ...registration, stateCircuitVersion: BigInt(c.stateCircuitVersion) + 1n }], "UnsupportedVersion");
        }
        trackMap("StateCertificationRegistryV3", "states", state); trackMap("StateCertificationRegistryV3", "usedProofHashes", hashProof(a));
        await send("StateCertificationRegistryV3", "certifyState", [request, a.proof, a.signals], "certify_stage_a", "primary", i);
        const record = await read("StateCertificationRegistryV3", "getState", [state]) as Record<string, unknown>;
        assert.equal(record.stateCommitment, a.signals[8]); assert.equal(record.proofHash, hashProof(a)); assert.equal(record.stateCircuitVersion, BigInt(c.stateCircuitVersion));
        const inputRecord = await read("InputCommitmentRegistryV3", "getRequest", [request]) as Record<string, unknown>;
        assert.equal(inputRecord.consumed, true); assert.equal(inputRecord.stateId, state);
        reusedState = state; reusedRequest = request;
      }
      assert.equal(await read("ExplanationGroth16VerifierV3", "verifyProof", [b.proof.a, b.proof.b, b.proof.c, b.signals]), true, "Actual Stage B Groth16 verifier control must accept");
      const n = nonce(`${c.id ?? "large_200_64_32_16"}:certificate:${i}`), cert = certificateId(state, b, n);
      if (i === 0) {
        const wrongState = [...b.signals]; wrongState[8] = (wrongState[8] + 1n) % SCALAR_FIELD;
        await reject("mismatched_certified_state", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, wrongState, n], "RegistryBindingReject");
        const mask = [...b.signals]; mask[14] = 0n;
        await reject("forbidden_policy_mask", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, mask, n], "RegistryBindingReject");
        const sparse = [...b.signals]; sparse[14+c.C] = 2n;
        await reject("substituted_sparsity_bound_2", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, sparse, n], "RegistryBindingReject");
        const l1 = [...b.signals]; l1[15+c.C] = 4001n;
        await reject("substituted_l1_bound_4001", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, l1, n], "RegistryBindingReject");
        const wrongExplanation = [...b.signals]; wrongExplanation[16+c.C] = (wrongExplanation[16+c.C] + 1n) % SCALAR_FIELD;
        await reject("modified_explanation_commitment", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, wrongExplanation, n], "Groth16VerificationFalse");
        const staleCircuit = [...b.signals]; staleCircuit[12] += 1n;
        await reject("mismatched_stage_b_circuit", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, staleCircuit, n], "RegistryBindingReject");
        await reject("uncertified_state", "ExplanationCertificateRegistryV3", "certifyExplanation", [nonce("missing-state"), b.proof, b.signals, n], "RegistryBindingReject");
        await reject("tampered_stage_b_proof", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, { ...b.proof, a: [0n, 0n] }, b.signals, n], "Groth16VerificationFalse");
      }
      trackMap("ExplanationCertificateRegistryV3", "certificates", cert); trackMap("ExplanationCertificateRegistryV3", "usedProofHashes", hashProof(b)); trackMap("ExplanationCertificateRegistryV3", "usedCertificateNonces", n);
      assert.ok(wallets[1], "Independent local proof submitter required");
      await send("ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, b.signals, n], "certify_stage_b", "primary", i, wallets[1]);
      const certificate = await read("ExplanationCertificateRegistryV3", "getCertificate", [cert]) as Record<string, unknown>;
      assert.equal(certificate.stateId, state); assert.equal(certificate.proofHash, hashProof(b)); assert.equal(certificate.counterfactualPrediction, 0);
      assert.equal(certificate.explanationCommitment,b.signals[16+c.C],"Certificate must identify the exact committed private explanation");
      certificates.push(cert); stateIds.push(state);
      if (i === 0) {
        await reject("replayed_state_proof", "StateCertificationRegistryV3", "certifyState", [request, a.proof, a.signals], "ReplayReject");
        await reject("replayed_explanation_proof", "ExplanationCertificateRegistryV3", "certifyExplanation", [state, b.proof, b.signals, nonce("replay-new-public-nonce")], "ReplayReject");
        await reject("duplicate_certificate", "ExplanationCertificateRegistryV3", "certifyExplanation", [state,b.proof,b.signals,n], "DuplicateReject");
        // Isolate the public nonce guard before Groth16 verification.
        await reject("replayed_certificate_nonce","ExplanationCertificateRegistryV3","certifyExplanation",[state,{...b.proof,a:[0n,0n]},b.signals,n],"ReplayReject");

      }
      const primary = transactions.filter(t => t.phase === "primary");
      if ([1, 2, 5, 10, 20, 50].includes(i + 1)) {
        const observed = (await snapshot()).filter(o => BigInt(o.value) !== 0n);
        const setupSlots = setupStorage.filter(o => BigInt(o.value) !== 0n).length;
        prefixes.push({ m: i + 1, actualExecuted: true, stageACertifications: primary.filter(t => t.action === "certify_stage_a").length, stageBCertifications: i + 1, primaryTransactions: primary.length, primaryGas: primary.reduce((s, t) => s + BigInt(t.gasUsed), 0n), primaryCalldataBytes: primary.reduce((s, t) => s + t.calldataBytes, 0), observedNonzeroSlots: observed.length, observedNonzeroBytes: observed.length * 32, setupObservedNonzeroSlots: setupSlots, primaryObservedNonzeroSlots: observed.length - setupSlots, primaryObservedNonzeroBytes: (observed.length - setupSlots) * 32 });
      }
    }
    await send("ModelRegistryV3", "deactivateModel", [1n], "deactivate_for_security_test", "security");
    const last = pairs[pairs.length - 1].b;
    await reject("deactivated_model", "ExplanationCertificateRegistryV3", "certifyExplanation", [stateIds[stateIds.length - 1], last.proof, last.signals, nonce("after-deactivation")], "StaleModelReject");
    return { strategy, workflowWallSeconds:Number(process.hrtime.bigint()-strategyStarted)/1e9, status: "PASS", primaryFlowCount: pairs.length, validStageAProofsAccepted: 1, validStageBProofsAccepted: pairs.length, certifiedStateBindingValidated: true, permissionlessStageBSubmissionValidated: true, publicSignalCountA: 12, publicSignalCountB: 17 + c.C, publicSignalAbiBytesA: 12 * 32, publicSignalAbiBytesB: (17 + c.C) * 32, transactions, prefixes, negatives, negativeCount: negatives.length, certificatesRetrieved: certificates.length, certificateIds: certificates, storageScope: "Nonzero 32-byte words at all compiler-derived static and created mapping record/replay slots. Mapping roots do not themselves allocate record storage. This is observed contract state, not calldata or proof memory. Prefix totals include setup words; primaryObservedNonzeroSlots subtracts the actually observed setup baseline.", setupStorage };
  } finally { await connection.close(); }
}


export type ServerManifest={mode:"synthetic_stress";configuration:unknown;strategy?:"reuse";runRoot?:string;modelArtifactKeccak:Hex;schemaManifestKeccak:Hex;pairs:{stageA:ProofFiles;stageB:ProofFiles}[];verifiers:{stageA:string;stageB:string};policyManifest?:unknown;validation_mode?:"smoke"|"full"};
export async function run(manifestPath:string,outputPath:string,options:{smoke?:boolean}={}):Promise<Record<string,unknown>> {
 const started=process.hrtime.bigint();
 manifestPath=containedFile(manifestPath);outputPath=containedOutput(outputPath);
 assert.ok(!existsSync(outputPath),"A completed chain result is immutable; use a new run directory");
 const incoming=json<ServerManifest>(manifestPath);assert.equal(incoming.mode,'synthetic_stress');
 assert.ok(incoming.validation_mode===undefined||incoming.validation_mode==='smoke'||incoming.validation_mode==='full');
 const smoke=options.smoke===true||incoming.validation_mode==='smoke',requiredPairs=incoming.pairs.length;
 assert.ok(Number.isSafeInteger(requiredPairs)&&requiredPairs>=2,'At least two explanation proofs are required to validate certified-state reuse');
 const c=normalizeConfiguration(incoming.configuration),strategy=incoming.strategy??c.strategy;assert.equal(strategy,c.strategy);
 if(incoming.policyManifest!==undefined)validatePolicyManifest(c,incoming.policyManifest);
 assert.ok(/^0x[0-9a-fA-F]{64}$/.test(incoming.modelArtifactKeccak)&&/^0x[0-9a-fA-F]{64}$/.test(incoming.schemaManifestKeccak));
 const manifest:Manifest={mode:incoming.mode,configuration:c,modelArtifactKeccak:incoming.modelArtifactKeccak,schemaManifestKeccak:incoming.schemaManifestKeccak,verifierSources:incoming.verifiers,
  reuse:{stageA:incoming.pairs[0].stageA,explanations:incoming.pairs.map(p=>p.stageB)}};
 for(const pair of incoming.pairs)assert.deepEqual(pair.stageA,incoming.pairs[0].stageA,"Every explanation must reference the selected A proof");
 const runRoot=containedOutput(incoming.runRoot??resolve(dirname(outputPath),'../..')),target=containedOutput(join(runRoot,'chain'));
 const sources=generateContracts(c,incoming.verifiers,target);
 process.env.HARDHAT_CONFIG=hardhatConfig(target);
 process.env.HARDHAT_DISABLE_TELEMETRY='true';process.env.DO_NOT_TRACK='1';
 const {default:hre}=await import('hardhat');
 const compilationStart=process.hrtime.bigint(),built=await hre.solidity.build(await hre.solidity.getRootFilePaths());
 assert.equal(hre.solidity.isSuccessfulBuildResult(built),true,'All staged registries and real verifier exports must compile');
 const compilationSeconds=Number(process.hrtime.bigint()-compilationStart)/1e9,layouts={} as Record<ContractName,StorageLayout>;
 for(const name of NAMES){
  const buildId=await hre.artifacts.getBuildInfoId(name);assert.ok(buildId);
  const path=await hre.artifacts.getBuildInfoOutputPath(buildId);assert.ok(path);
  const info=json<{output:{contracts:Record<string,Record<string,{storageLayout:StorageLayout}>>}}>(path);
  const found=Object.values(info.output.contracts).map(f=>f[name]).find(Boolean);assert.ok(found);layouts[name]=found.storageLayout;
 }
 const observation=await runStrategy(hre,manifest,layouts,requiredPairs);
 assert.equal(observation.validStageAProofsAccepted,1);assert.equal(observation.validStageBProofsAccepted,requiredPairs);assert.equal(observation.certificatesRetrieved,requiredPairs);
 assert.equal(observation.negativeCount,21,'All decoded chain attacks must actually reject');
 const result={status:smoke?'SMOKE_PASS':'PASS',certificatesRetrieved:observation.certificatesRetrieved,validStageAProofsAccepted:observation.validStageAProofsAccepted,validStageBProofsAccepted:observation.validStageBProofsAccepted,securityNegativeCount:observation.negativeCount,validation_mode:smoke?'smoke':'full',requestedExplanations:requiredPairs,mode:incoming.mode,actualExecution:true,configuration:c,strategy,environment:{chain:'local Hardhat EDR',chainId:31337,hardfork:'prague',compiler:'solc 0.8.37',optimizerRuns:200,developmentOnly:true,setupSecurity:'DEV_INSECURE'},compilationSeconds,workflowWallSeconds:Number(process.hrtime.bigint()-started)/1e9,manifestSha256:createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),contractSourceIdentities:sources,storageLayouts:layouts,strategies:[observation],costBoundaries:{deploymentAndSetupExcludedFromPrimary:true,primary:['anchor_input','certify_stage_a','certify_stage_b'],securityTransactionsExcludedFromPrimary:true,noMainnetMonetaryCosts:true,wholeProcessCpuAndRssRecordedByParentRunner:true}};
 mkdirSync(dirname(outputPath),{recursive:true});writeFileSync(outputPath,serial(result),{flag:'wx'});
 const csvPath=containedOutput(join(dirname(outputPath),'blockchain_runs.csv'));
 const fields=['mode','status','measurement_type','strategy','phase','action','candidate','transactionHash','blockNumber','gasUsed','calldataBytes','wallSeconds','observedNonzeroSlotsAfter','observedNonzeroBytesAfter'];
 const rows=observation.transactions.map(t=>({mode:incoming.mode,measurement_type:'ACTUAL',...t,...(t.storage??{})}));
 const cell=(value:unknown)=>JSON.stringify(value===undefined?'':String(value));
 writeFileSync(csvPath,fields.join(',')+'\n'+rows.map(row=>fields.map(key=>cell((row as Record<string,unknown>)[key])).join(',')).join('\n')+'\n',{flag:'wx'});return result;
}
const args=process.argv.slice(2);
if(args.includes('--manifest')){
 const m=args[args.indexOf('--manifest')+1],o=args[args.indexOf('--output')+1];assert.ok(m&&o&&args.includes('--output'));
 const result=await run(m,o,{smoke:args.includes('--smoke')});console.log(serial({status:result.status,output:o}));
}
