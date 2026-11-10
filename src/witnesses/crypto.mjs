// See THIRD_PARTY_NOTICES.md for source attribution.
// Private inputs arrive on stdin; errors never print request or witness values.
import {readFileSync,writeFileSync,mkdirSync,chmodSync,statSync,lstatSync,realpathSync,openSync,closeSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {createRequire} from 'node:module';
import {groth16,powersOfTau,zKey,r1cs,wtns} from 'snarkjs';
import {keccak256} from 'viem';
const logger={info(){},warn(){},error(){},debug(){},log(){}};
function privateOutput(path){
  const p=resolve(path), parent=dirname(p);
  if(realpathSync(parent)!==parent || lstatSync(parent).isSymbolicLink() || (statSync(parent).mode&0o777)!==0o700)throw Error('Private directory required');
  closeSync(openSync(p,'wx',0o600));
}
function save(path,value){writeFileSync(path,JSON.stringify(value));}
let curve;
try {
 const q=JSON.parse(readFileSync(0,'utf8'));let result;
 switch(q.op){
 case 'keccak':result={hash:keccak256('0x'+q.hex)};break;
 case 'ptau-new':{
  const require=createRequire(import.meta.resolve('snarkjs'));const {buildBn128}=await import(require.resolve('ffjavascript'));
  curve=await buildBn128(true);await powersOfTau.newAccumulator(curve,q.power,q.output,logger);result={status:'PASS',power:q.power};break;
 }
 case 'ptau-contribute':await powersOfTau.contribute(q.input,q.output,'DEV_INSECURE local demonstration',q.entropy,logger);result={status:'PASS'};break;
 case 'ptau-prepare':await powersOfTau.preparePhase2(q.input,q.output,logger);result={status:'PASS'};break;
 case 'ptau-verify':result={valid:await powersOfTau.verify(q.input,logger)};break;
 case 'setup':await zKey.newZKey(q.r1cs,q.ptau,q.output,logger);if(!statSync(q.output).size)throw Error('Empty key');result={status:'PASS'};break;
 case 'contribute':await zKey.contribute(q.input,q.output,'DEV_INSECURE local demonstration',q.entropy,logger);result={status:'PASS'};break;
 case 'key-verify':result={valid:await zKey.verifyFromR1cs(q.r1cs,q.ptau,q.zkey,logger)};break;
 case 'export':{
  save(q.vk,await zKey.exportVerificationKey(q.zkey));
  const require=createRequire(import.meta.url);const root=resolve(dirname(require.resolve('snarkjs')),'..');
  const template=readFileSync(resolve(root,'templates/verifier_groth16.sol.ejs'),'utf8');
  const solidity=await zKey.exportSolidityVerifier(q.zkey,{groth16:template},logger);
  writeFileSync(q.solidity,solidity.replace('contract Groth16Verifier','contract '+q.contract));
  result={status:'PASS'};break;
 }
 case 'info':{
  const info=await r1cs.info(q.r1cs,logger);curve=info.curve;
  result={constraints:info.nConstraints,wires:info.nVars,publicInputs:info.nPubInputs,privateInputs:info.nPrvInputs,publicOutputs:info.nOutputs};break;
 }
 case 'witness':privateOutput(q.output);await wtns.calculate(JSON.parse(readFileSync(q.input,'utf8')),q.wasm,q.output,{sanityCheck:true});chmodSync(q.output,0o600);result={status:'PASS'};break;
 case 'expect-reject':{
  privateOutput(q.output);
  try{await wtns.calculate(JSON.parse(readFileSync(q.input,'utf8')),q.wasm,q.output,{sanityCheck:true});result={rejected:false};}
  catch(error){if(!/Assert Failed|assertion failed/i.test(String(error?.message??error)))throw Error('Witness infrastructure');result={rejected:true,layer:'CIRCUIT_ASSERTION'};}
  break;
 }
 case 'witness-check':result={valid:await wtns.check(q.r1cs,q.witness,logger)};break;
 case 'inspect':{
  const witness=await wtns.exportJson(q.witness);result={matched:q.indices.every((index,i)=>String(witness[index])===String(q.expected[i]))};break;
 }
 case 'mutate-witness':{
  const bytes=Buffer.from(readFileSync(q.witness));let position=12,section,prime;
  for(let i=0;i<bytes.readUInt32LE(8);i++){const kind=bytes.readUInt32LE(position),length=Number(bytes.readBigUInt64LE(position+4));position+=12;
   if(kind===1){const n=bytes.readUInt32LE(position);prime=0n;for(let j=n-1;j>=0;j--)prime=prime*256n+BigInt(bytes[position+4+j]);}
   if(kind===2)section=position;position+=length;}
  if(section===undefined||prime===undefined)throw Error('WTNS format');const offset=section+32*q.index;
  let value=0n;for(let j=31;j>=0;j--)value=value*256n+BigInt(bytes[offset+j]);value=(value+1n)%prime;
  for(let j=0;j<32;j++){bytes[offset+j]=Number(value&255n);value>>=8n;}privateOutput(q.output);writeFileSync(q.output,bytes);result={status:'PASS'};break;
 }
 case 'prove':{
  const {proof,publicSignals}=await groth16.prove(q.zkey,q.witness,undefined,{singleThread:true});save(q.proof,proof);save(q.public,publicSignals);result={status:'PASS'};break;
 }
 case 'verify':{
  const vk=JSON.parse(readFileSync(q.vk,'utf8')),signals=JSON.parse(readFileSync(q.public,'utf8')),proof=JSON.parse(readFileSync(q.proof,'utf8'));
  result={valid:await groth16.verify(vk,signals,proof)};break;
 }
 default:throw Error('Unsupported operation');
 }
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{process.stderr.write('CRYPTOGRAPHIC_OPERATION_FAILED\n');process.exitCode=1;}
finally{if(curve?.terminate)await curve.terminate();if(globalThis.curve_bn128!==curve&&globalThis.curve_bn128?.terminate)await globalThis.curve_bn128.terminate();}
