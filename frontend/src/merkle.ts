// Client-side Merkle Mountain Range verification.
//
// Mirrors `MerkleTree::verify_inclusion` and `MerkleTree::verify_consistency`
// in crates/core/src/merkle.rs. Hashes use domain separation: leaf nodes are
// `SHA256(0x00 || data)` and internal nodes are `SHA256(0x01 || left || right)`.

import { ConsistencyProof, InclusionProof, ProofStep } from './api';

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function hashLeaf(data: Uint8Array): Promise<string> {
  const prefix = new Uint8Array([0]);
  return bytesToHex(await sha256(concat(prefix, data)));
}

export async function hashPairHex(left: string, right: string): Promise<string> {
  const prefix = new Uint8Array([1]);
  return bytesToHex(await sha256(concat(prefix, hexToBytes(left), hexToBytes(right))));
}

/** Walk a node hash up through sibling steps (bottom-up). */
async function walkUp(hash: string, steps: ProofStep[]): Promise<string> {
  let current = hash;
  for (const step of steps) {
    current = step.sibling_is_left
      ? await hashPairHex(step.hash, current)
      : await hashPairHex(current, step.hash);
  }
  return current;
}

/** Fold MMR peaks left to right into the tree root ('' for no peaks). */
export async function foldPeaks(peaks: string[]): Promise<string> {
  let acc: string | null = null;
  for (const peak of peaks) {
    acc = acc === null ? peak : await hashPairHex(acc, peak);
  }
  return acc ?? '';
}

export async function verifyInclusion(
  proof: InclusionProof,
  leafHash: string,
  root: string,
): Promise<boolean> {
  if (proof.peak_index >= proof.peaks.length) return false;
  const atPeak = await walkUp(leafHash, proof.sibling_path);
  if (atPeak !== proof.peaks[proof.peak_index]) return false;
  const recomputed = proof.peaks.map((p, i) => (i === proof.peak_index ? atPeak : p));
  return (await foldPeaks(recomputed)) === root;
}

/** Canonical (level, leaf_start) pairs for a tree of `size` leaves,
 *  in left-to-right leaf order (descending level). */
export function frontierRanges(size: number): { level: number; start: number }[] {
  const out: { level: number; start: number }[] = [];
  let start = 0;
  for (let level = 47; level >= 0; level -= 1) {
    if (size & (1 << level)) {
      out.push({ level, start });
      start += 1 << level;
    }
  }
  return out;
}

export async function verifyConsistency(
  proof: ConsistencyProof,
  oldRoot: string,
  newRoot: string,
): Promise<boolean> {
  const expected = frontierRanges(proof.old_tree_size);
  if (proof.peak_proofs.length === 0 || expected.length !== proof.peak_proofs.length) {
    return false;
  }
  let oldAcc: string | null = null;
  for (let i = 0; i < expected.length; i += 1) {
    const pp = proof.peak_proofs[i];
    if (pp.level !== expected[i].level || pp.leaf_start !== expected[i].start) {
      return false;
    }
    const atNewPeak = await walkUp(pp.peak_hash, pp.steps);
    if (atNewPeak !== proof.peaks[pp.new_peak_index]) return false;
    oldAcc = oldAcc === null ? pp.peak_hash : await hashPairHex(oldAcc, pp.peak_hash);
  }
  if (oldAcc !== oldRoot) return false;
  return (await foldPeaks(proof.peaks)) === newRoot;
}

/** Truncate a hex hash for display. */
export function shortHash(hash: string, chars = 16): string {
  if (!hash) return '';
  return hash.length > chars * 2 ? `${hash.slice(0, chars)}…${hash.slice(-8)}` : hash;
}