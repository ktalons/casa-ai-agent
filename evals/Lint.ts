#!/usr/bin/env bun
// *****************************************************************************
// *Title: Fabrication Lint CLI*
// *Author: Kyle Versluis*
// *Description: Fails a brief or finding whose evidence tokens do not trace.*
// *****************************************************************************

/**
 * Every rule ID, alert ID, host, ATT&CK ID, CSF ID, IPv4 and IPv6 literal, user, event ID,
 * port, domain, hash and timestamp in a brief or a finding must trace to the intake it was
 * produced from, or to a reference table. Exit 1 on any unknown token.
 *
 *   bun evals/Lint.ts --brief briefs/<file>.brief.md --intake <intake.json>
 *   bun evals/Lint.ts --finding <finding.json|md> --intake <intake.json> [--json]
 *   bun evals/Lint.ts ... --host-prefix <prefix>
 *
 * Known hosts come from the intake itself. --host-prefix is an optional override that also
 * treats any token starting with the prefix as a host; it is a plain prefix, validated and escaped.
 */

// *--- Imports ---*

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assertHostPrefix, KINDS, lint } from "./lib/extract.ts";

// *--- Entry Point ---*

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const brief = arg("--brief");
const finding = arg("--finding");
const intakePath = arg("--intake");
const hostPrefix = arg("--host-prefix");
const asJson = process.argv.includes("--json");

if ((!brief && !finding) || !intakePath) {
  console.error("usage: bun evals/Lint.ts (--brief <md> | --finding <json|md>) --intake <intake.json> [--host-prefix <prefix>] [--json]");
  process.exit(2);
}
if (hostPrefix !== undefined) {
  try { assertHostPrefix(hostPrefix); } catch (e) { console.error(`--host-prefix: ${(e as Error).message}`); process.exit(2); }
}

const docPath = (brief ?? finding) as string;
const text = readFileSync(docPath, "utf8");
const intakeRaw = readFileSync(intakePath);
const intake = JSON.parse(intakeRaw.toString("utf8"));
const intakeSha256 = createHash("sha256").update(intakeRaw).digest("hex");
const result = lint(text, intake, { hostPrefix, intakeSha256 });

if (asJson) {
  console.log(JSON.stringify({ document: docPath, intake: intakePath, ...result }, null, 2));
} else {
  const c = result.counts;
  console.log(`${docPath}: ${KINDS.filter((k) => c[k] > 0).map((k) => `${c[k]} ${k}`).join(", ") || "no evidence tokens"}`);
  const b = result.beyond_intake;
  if (b.attack.length) console.log(`  info: ATT&CK IDs cited beyond the intake's own: ${b.attack.join(", ")}`);
  if (b.event_id.length) console.log(`  info: event IDs from the reference table, not in the intake: ${b.event_id.join(", ")}`);
  if (b.port.length) console.log(`  info: service ports from the reference table, not in the intake: ${b.port.join(", ")}`);
  for (const n of result.notes) console.log(`  note: ${n}`);
  if (result.pass) console.log("  ✓ every citation traces to the intake or a reference table");
  else for (const u of result.unknown) console.log(`  ✗ ${u.kind} ${u.token} — ${u.reason}`);
}
process.exit(result.pass ? 0 : 1);
