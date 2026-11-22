// *****************************************************************************
// *Title: Plugin Icon Check Tests*
// *Author: Kyle*
// *Description: Checks the size rules the plugin directory sets for an icon.*
// *****************************************************************************

// *--- Imports ---*

import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkIcon, MAX_BYTES } from "./check-icon.ts";

// *--- Helpers ---*

/** The first 24 bytes of a PNG with the given size, padded to `total` bytes. */
function png(width: number, height: number, total = 64): Uint8Array {
  const bytes = new Uint8Array(total);
  bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
  const view = new DataView(bytes.buffer);
  view.setUint32(16, width);
  view.setUint32(20, height);
  return bytes;
}

// *--- Size rules (ISC-40) ---*

test("icon: a square PNG at either bound passes", () => {
  for (const side of [512, 1024, 2048]) expect(checkIcon(png(side, side))).toEqual({ ok: true, width: side, height: side, problems: [] });
});

test("icon: one pixel outside either bound fails", () => {
  expect(checkIcon(png(511, 511)).ok).toBe(false);
  expect(checkIcon(png(2049, 2049)).ok).toBe(false);
});

test("icon: a PNG that is not square fails and says so", () => {
  const r = checkIcon(png(1024, 1023));
  expect(r.ok).toBe(false);
  expect(r.problems.join(" ")).toContain("not square");
});

test("icon: a file at the size limit passes and one byte over fails", () => {
  expect(checkIcon(png(1024, 1024, MAX_BYTES)).ok).toBe(true);
  expect(checkIcon(png(1024, 1024, MAX_BYTES + 1)).ok).toBe(false);
});

test("icon: bytes that are not a PNG fail without a size", () => {
  const jpeg = new Uint8Array(64);
  jpeg.set([0xff, 0xd8, 0xff, 0xe0]);
  expect(checkIcon(jpeg)).toEqual({ ok: false, problems: ["not a PNG file"] });
  expect(checkIcon(png(1024, 1024).slice(0, 20)).ok).toBe(false);
  const noHeader = png(1024, 1024);
  noHeader[12] = 0x74;
  expect(checkIcon(noHeader).ok).toBe(false);
});

// *--- The icon the plugin carries ---*

test("icon: the plugin's own icon meets the rules", () => {
  const r = checkIcon(new Uint8Array(readFileSync(join(import.meta.dir, "..", ".claude-plugin", "icon.png"))));
  expect(r.problems).toEqual([]);
  expect(r.ok).toBe(true);
});
