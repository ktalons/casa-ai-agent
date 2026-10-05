#!/usr/bin/env bun
/**
 * refresh-csf.ts — regenerate skills/standards/references/csf-2.0.json from the official NIST
 * CPRT export of the CSF 2.0 Core. Network required (csrc.nist.gov). Zero dependencies.
 *
 *   bun scripts/refresh-csf.ts
 *
 * Withdrawn CSF 1.1 elements that the export still carries are excluded, which leaves the
 * 6 functions, 22 categories and 106 subcategories of CSF 2.0.
 */
import { join } from "node:path";

const URL = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all";
const OUT = join(import.meta.dir, "..", "skills", "standards", "references", "csf-2.0.json");

type El = { element_type: string; element_identifier: string; title?: string; text?: string };

const cprt = (await (await fetch(URL)).json()) as { response: { elements: { elements: El[] } } };
const els = cprt.response.elements.elements;
// A withdrawn CSF 1.1 element X is represented by a "withdraw_reason" element named "WR-X"
// whose relationships point at the 2.0 element it was incorporated into. The withdrawn set
// is therefore the WR- identifiers with the prefix removed, never the relationship targets.
const withdrawn = new Set(
  els.filter((e) => e.element_type === "withdraw_reason" && e.element_identifier.startsWith("WR-")).map((e) => e.element_identifier.slice(3)),
);
const live = (type: string) => els.filter((e) => e.element_type === type && !withdrawn.has(e.element_identifier));
const clean = (s: unknown) => String(s ?? "").replace(/\s+/g, " ").trim();
const byId = (a: El, b: El) => a.element_identifier.localeCompare(b.element_identifier);
const table = (type: string, field: "title" | "text") => Object.fromEntries(live(type).sort(byId).map((e) => [e.element_identifier, clean(e[field] || e.title)]));

const out = {
  schema: "casa.csf/v1",
  source: "NIST Cybersecurity Framework (CSF) 2.0 Core, NIST CSWP 29 (February 2024), via the NIST CPRT export (document CSF_2_0_0)",
  verification: { ids_verified: true, verified_on: new Date().toISOString().slice(0, 10), note: "Functions, categories and subcategory outcome statements are the official CPRT text; withdrawn CSF 1.1 elements are excluded. Regenerate with scripts/refresh-csf.ts." },
  functions: table("function", "title"),
  categories: table("category", "title"),
  subcategories: table("subcategory", "text"),
};
const n = (o: object) => Object.keys(o).length;
if (n(out.functions) !== 6 || n(out.categories) !== 22 || n(out.subcategories) !== 106) throw new Error(`unexpected counts: ${n(out.functions)}/${n(out.categories)}/${n(out.subcategories)}`);
await Bun.write(OUT, JSON.stringify(out, null, 1) + "\n");
console.error(`wrote ${n(out.subcategories)} subcategories to ${OUT}`);
