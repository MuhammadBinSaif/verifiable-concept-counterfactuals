import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync,mkdirSync,writeFileSync,symlinkSync,existsSync,rmSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';
import {keccak256,toBytes} from 'viem';
import {adaptProtocolSources,normalizeConfiguration,policyManifest,validatePolicyManifest,run,canonical,hardhatConfig} from '../src/blockchain/run.ts';
import {normalizeProof,SCALAR_FIELD} from '../src/blockchain/protocol.ts';

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(import.meta.url),solc=require('solc');
function cfg(id:string){return JSON.parse(readFileSync(resolve(ROOT,`configs/${id}.json`),'utf8'));}
for(const id of ['s1','s2','s3']){
 test(`${id}: registries compile with the configuration-specific public layout`,()=>{
  const c=normalizeConfiguration(cfg(id)),sources=adaptProtocolSources(c);
  assert.ok(solc.version().startsWith('0.8.37'));
  const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{optimizer:{enabled:true,runs:200},evmVersion:'prague',outputSelection:{'*':{'*':['abi','evm.bytecode','evm.deployedBytecode','storageLayout']}}}})));
  assert.deepEqual((compiled.errors??[]).filter((e:any)=>e.severity==='error'),[]);
  const a=compiled.contracts['contracts/protocol/StateCertificationRegistryV3.sol'].StateCertificationRegistryV3;
  const b=compiled.contracts['contracts/protocol/ExplanationCertificateRegistryV3.sol'].ExplanationCertificateRegistryV3;
  assert.equal(a.abi.find((x:any)=>x.name==='certifyState').inputs[2].type,'uint256[12]');
  assert.equal(b.abi.find((x:any)=>x.name==='certifyExplanation').inputs[2].type,`uint256[${17+c.C}]`);
  assert.equal(b.abi.find((x:any)=>x.name==='calculateProofHash').inputs[1].type,`uint256[${17+c.C}]`);
  assert.ok(a.evm.bytecode.object.length>0&&b.evm.bytecode.object.length>0);
  const source=sources['contracts/protocol/ExplanationCertificateRegistryV3.sol'].content;
  for(let index=0;index<c.C;index++)assert.ok(source.includes(`_match(ALLOWED_MASK_${index}_INDEX, publicSignals[ALLOWED_MASK_${index}_INDEX], 1);`));
  assert.ok(!source.includes(`ALLOWED_MASK_${c.C}_INDEX`));
  assert.ok(source.includes(`SPARSITY_BOUND_INDEX = ${14+c.C};`));
  assert.ok(source.includes(`L1_BOUND_INDEX = ${15+c.C};`));
  assert.ok(source.includes(`EXPLANATION_COMMITMENT_INDEX = ${16+c.C};`));
  assert.ok(source.includes('_match(SPARSITY_BOUND_INDEX, publicSignals[SPARSITY_BOUND_INDEX], 1);'));
  assert.ok(source.includes('_match(L1_BOUND_INDEX, publicSignals[L1_BOUND_INDEX], 4000);'));
  assert.ok(source.includes('usedProofHashes[proofHash]')&&source.includes('usedCertificateNonces[certificateNonce]'));
  assert.ok(source.includes('if (!verifier.verifyProof('));
  assert.ok(source.includes('explanationCommitment: publicSignals[EXPLANATION_COMMITMENT_INDEX]'));
  const record=b.abi.find((x:any)=>x.name==='getCertificate').outputs[0].components;
  assert.equal(record.find((x:any)=>x.name==='explanationCommitment').type,'uint256');
  assert.ok(!record.some((x:any)=>x.name==='explanationNonce'||x.name==='cPrimeQ'));
  const iface=compiled.contracts['contracts/interfaces/IVerifiers.sol'];
  assert.equal(iface.IExplanationGroth16VerifierV3.abi.find((x:any)=>x.name==='verifyProof').inputs[3].type,`uint256[${17+c.C}]`);
 });
 test(`${id}: exact policy binding rejects substituted fields and digests`,()=>{
  const c=normalizeConfiguration(cfg(id)),manifest=policyManifest(c);
  assert.equal(validatePolicyManifest(c,manifest),keccak256(toBytes(canonical(manifest.policy))));
  for(const [field,value] of [['sparsityBound',2],['l1Bound',4001],['conceptDimensions',c.C+1],['direction','any'],['stateCircuitVersion',101]]){
   const bad=structuredClone(manifest);bad.policy[field as string]=value;
   assert.throws(()=>validatePolicyManifest(c,bad));
   bad.canonicalUtf8=canonical(bad.policy);bad.keccak256=keccak256(toBytes(bad.canonicalUtf8));
   assert.throws(()=>validatePolicyManifest(c,bad));
  }
 });
}
test('configuration identity rejects altered shape, policy and circuit version',()=>{
 const version=cfg('s1');version.versions.stateCircuitVersion=203;
 assert.throws(()=>normalizeConfiguration(version),/version/);
 const shape=cfg('s2');shape.architecture=[19,16,4,2];
 assert.throws(()=>normalizeConfiguration(shape),/Architecture/);
 const policy=cfg('s3');policy.policy.sparsity_bound=2;
 assert.throws(()=>normalizeConfiguration(policy),/policy/);
});
test('chain output cannot escape the release directory',async()=>{
 await assert.rejects(run(resolve(ROOT,'configs/s1.json'),resolve(ROOT,'../would_overwrite.json')),/release directory/);
});
test('Hardhat config rejects a dangling output symlink',()=>{
 const target=resolve(ROOT,'.runtime/chain-tests/dangling_config');mkdirSync(target,{recursive:true});
 const output=resolve(target,'hardhat.config.ts'),outside=resolve(ROOT,'.runtime/chain-tests/dangling_target.ts');
 rmSync(output,{force:true});rmSync(outside,{force:true});symlinkSync(outside,output);
 try{assert.throws(()=>hardhatConfig(target),/symlink/);assert.equal(existsSync(outside),false);}
 finally{rmSync(output,{force:true});}
});
test('reuse validation requires at least two explanations before loading proofs',async()=>{
 const path=resolve(ROOT,'.runtime/chain-tests/single_pair.json');mkdirSync(dirname(path),{recursive:true});
 writeFileSync(path,JSON.stringify({mode:'synthetic_stress',configuration:cfg('s1'),pairs:[{stageA:{proof:'missing',public:'missing'},stageB:{proof:'missing',public:'missing'}}]}));
 await assert.rejects(run(path,resolve(ROOT,'.runtime/chain-tests/must_not_exist.json')),/At least two/);
});
test('proof coordinates are exact and G2 order matches the Solidity ABI',()=>{
 const raw={protocol:'groth16',curve:'bn128',pi_a:['1','2','1'],pi_b:[['3','4'],['5','6'],['1','0']],pi_c:['7','8','1']};
 assert.deepEqual(normalizeProof(raw),{a:[1n,2n],b:[[4n,3n],[6n,5n]],c:[7n,8n]});
 const malformed=structuredClone(raw);malformed.pi_a[0]='01';assert.throws(()=>normalizeProof(malformed));
 assert.equal(SCALAR_FIELD.toString(),'21888242871839275222246405745257275088548364400416034343698204186575808495617');
});
test('local Hardhat config compiles the actual registry sources and initializes Prague',async()=>{
 const target=resolve(ROOT,'.runtime/chain-tests/hardhat');
 for(const [name,{content}] of Object.entries(adaptProtocolSources(cfg('s1')))){
  const output=resolve(target,name);mkdirSync(dirname(output),{recursive:true});writeFileSync(output,content);
 }
 process.env.HARDHAT_CONFIG=hardhatConfig(target);
 const {default:loaded}=await import('hardhat');const hre:any=loaded;
 const built=await hre.solidity.build(await hre.solidity.getRootFilePaths());
 assert.equal(hre.solidity.isSuccessfulBuildResult(built),true);
 const connection=await hre.network.create('hardhatMainnet');
 try{
  const client=await connection.viem.getPublicClient();
  assert.equal(await client.getChainId(),31337);
  assert.equal(connection.networkConfig.hardfork,'prague');
 }finally{await connection.close();}
});
