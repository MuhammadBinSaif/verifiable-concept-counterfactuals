// Private commitment payloads arrive on stdin and are never logged.
import {readFileSync} from 'node:fs';
import {buildPoseidon} from 'circomlibjs';
import {keccak256} from 'viem';
const FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function scalar(v){if(typeof v!=='string'||!/^(0|[1-9][0-9]*)$/.test(v))throw Error('Encoding');const n=BigInt(v);if(n>=FIELD)throw Error('Range');return n;}
try {
 const q=JSON.parse(readFileSync(0,'utf8'));let result;
 if(q.op==='keccak'){
  if(typeof q.hex!=='string'||!/^(?:[0-9a-f]{2})*$/.test(q.hex))throw Error('Hex');
  result={hash:keccak256('0x'+q.hex)};
 }else if(q.op==='commitments'){
  const p=await buildPoseidon(),h=items=>p.F.toObject(p(items));
  if(!Array.isArray(q.vectors)||q.vectors.length>16)throw Error('Request');
  const commitments=q.vectors.map(v=>{
   if(!Array.isArray(v.payload)||v.payload.length!==v.expectedLength)throw Error('Length');
   const payload=v.payload.map(scalar);
   if(v.kind==='model'){
    if(![403,2767,15511].includes(payload.length))throw Error('Model dimension');
    let acc=h([1006n,2n,BigInt(payload.length),8n]);
    for(let i=0;i<payload.length;i+=8){const chunk=payload.slice(i,i+8);while(chunk.length<8)chunk.push(0n);acc=h([acc,...chunk]);}
    return String(acc);
   }
   const lengths={1002:[15,23,39],1003:[22,67,203],1004:[22,30,46],1007:[10,14,22]};
   if(v.kind!=='sequence'||!lengths[v.domain]?.includes(payload.length))throw Error('Context');
   let acc=h([BigInt(v.domain),BigInt(payload.length)]);
   for(const value of payload)acc=h([acc,value]);
   return String(acc);
  });result={commitments};
 }else throw Error('Operation');
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{process.stderr.write('COMMITMENT_OPERATION_FAILED\n');process.exitCode=1;}
