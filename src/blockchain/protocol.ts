/** Exact integer/public-proof encoding. No verifier acceptance is simulated. */
import assert from "node:assert/strict";
export const SCALAR_FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BASE_FIELD=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export type Groth16Proof={a:[bigint,bigint];b:[[bigint,bigint],[bigint,bigint]];c:[bigint,bigint]};
function coordinate(value:unknown):bigint {
 assert.ok(typeof value==="string" && /^(0|[1-9][0-9]*)$/.test(value),"Exact decimal coordinates required");
 const result=BigInt(value);assert.ok(result<BASE_FIELD);return result;
}
export function normalizeProof(value:unknown):Groth16Proof {
 assert.ok(value && typeof value==="object" && !Array.isArray(value));
 const p=value as Record<string,unknown>;assert.equal(p.protocol,"groth16");assert.equal(p.curve,"bn128");
 const a=p.pi_a as unknown[],b=p.pi_b as unknown[][],c=p.pi_c as unknown[];
 assert.ok(Array.isArray(a)&&a.length===3&&Array.isArray(b)&&b.length===3&&b.every(x=>Array.isArray(x)&&x.length===2)&&Array.isArray(c)&&c.length===3);
 assert.equal(String(a[2]),"1");assert.equal(String(c[2]),"1");assert.deepEqual(b[2].map(String),["1","0"]);
 return {a:[coordinate(a[0]),coordinate(a[1])],b:[[coordinate(b[0][1]),coordinate(b[0][0])],[coordinate(b[1][1]),coordinate(b[1][0])]],c:[coordinate(c[0]),coordinate(c[1])]};
}
