#!/usr/bin/env bun
// *****************************************************************************
// *Title: Plugin Icon Check CLI*
// *Author: Kyle*
// *Description: Fails an icon the plugin directory would not accept.*
// *****************************************************************************

/**
 *   bun scripts/check-icon.ts [path]      (default .claude-plugin/icon.png)
 *
 * The plugin directory takes a square PNG of 512 to 2048 px a side, under 2 MB. This reads the
 * size from the file's own header, so it needs no image library. Exit 1 on any problem.
 */

// *--- Imports ---*

import { readFileSync } from "node:fs";
import { join } from "node:path";

// *--- Configuration ---*

export const MIN_SIDE = 512;
export const MAX_SIDE = 2048;
export const MAX_BYTES = 2 * 1024 * 1024;

const SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const IHDR = [0x49, 0x48, 0x44, 0x52];
// Signature (8), chunk length (4), chunk type (4), width (4), height (4).
const HEADER_BYTES = 24;

// *--- Types ---*

export interface IconResult { ok: boolean; width?: number; height?: number; problems: string[] }

// *--- Core Logic ---*

/** Checks the bytes of an icon file against the directory's rules. */
export function checkIcon(bytes: Uint8Array): IconResult {
  const isPng = bytes.length >= HEADER_BYTES && SIGNATURE.every((b, i) => bytes[i] === b) && IHDR.every((b, i) => bytes[12 + i] === b);
  if (!isPng) return { ok: false, problems: ["not a PNG file"] };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  const problems: string[] = [];
  if (width !== height) problems.push(`not square: ${width} x ${height}`);
  for (const side of new Set([width, height])) {
    if (side < MIN_SIDE || side > MAX_SIDE) problems.push(`side of ${side} px is outside ${MIN_SIDE} to ${MAX_SIDE}`);
  }
  if (bytes.length > MAX_BYTES) problems.push(`${bytes.length} bytes is over the ${MAX_BYTES} byte limit`);
  return { ok: problems.length === 0, width, height, problems };
}

// *--- Entry Point ---*

if (import.meta.main) {
  const path = process.argv[2] ?? join(import.meta.dir, "..", ".claude-plugin", "icon.png");
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(path));
  } catch {
    console.error(`✗ ${path}: cannot be read`);
    process.exit(1);
  }
  const r = checkIcon(bytes);
  if (!r.ok) {
    console.error(`✗ ${path}: ${r.problems.join("; ")}`);
    process.exit(1);
  }
  console.log(`✓ ${path}: ${r.width} x ${r.height} px, ${bytes.length} bytes`);
}
