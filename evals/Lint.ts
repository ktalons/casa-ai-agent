#!/usr/bin/env bun
/**
 * Lint.ts — the fabrication check. Every rule ID, host, ATT&CK ID, CSF ID and IPv4 literal
 * in a brief or a finding must trace to the intake it was produced from, or to a reference
 * table under skills/standards/references/. Exit 1 on any unknown token.
 *
 *   bun evals/Lint.ts --brief briefs/<file>.brief.md --intake intake/fixtures/<f>.intake.json
 *   bun evals/Lint.ts --finding <finding.json|md> --intake <intake.json> [--json]
 *   bun evals/Lint.ts ... --host-pattern '^talon[a-z0-9-]+$'
 *
 * The host pattern is the lab's naming convention and is a heuristic: a host that does not
 * match it is invisible to the host check (IP, rule-ID and technique checks still apply).
 */
import { readFileSync } from "node:fs";
import { lint, DEFAULT_HOST_PATTERN } from "./lib/extract.ts";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const brief = arg("--brief");
const finding = arg("--finding");
const intakePath = arg("--intake");
const hostPattern = arg("--host-pattern") ?? DEFAULT_HOST_PATTERN;
const asJson = process.argv.includes("--json");

if ((!brief && !finding) || !intakePath) {
  console.error("usage: bun evals/Lint.ts (--brief <md> | --finding <json|md>) --intake <intake.json> [--host-pattern <re>] [--json]");
  process.exit(2);
}

const docPath = (brief ?? finding) as string;
const text = readFileSync(docPath, "utf8");
const intake = JSON.parse(readFileSync(intakePath, "utf8"));
const result = lint(text, intake, hostPattern);

if (asJson) {
  console.log(JSON.stringify({ document: docPath, intake: intakePath, ...result }, null, 2));
} else {
  const c = result.counts;
  console.log(`${docPath}: ${c.rule_id} rule IDs, ${c.host} hosts, ${c.attack} ATT&CK IDs, ${c.csf} CSF IDs, ${c.ip} IPv4 literals`);
  if (result.attack_not_in_intake.length) console.log(`  info: ATT&CK IDs cited beyond the intake's own: ${result.attack_not_in_intake.join(", ")}`);
  if (result.pass) console.log("  ✓ every citation traces to the intake or a reference table");
  else for (const u of result.unknown) console.log(`  ✗ ${u.kind} ${u.token} — ${u.reason}`);
}
process.exit(result.pass ? 0 : 1);
