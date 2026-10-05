#!/usr/bin/env bun
/**
 * refresh-attack.ts — regenerate skills/standards/references/attack-techniques.json from
 * MITRE's own STIX 2.1 data (github.com/mitre-attack/attack-stix-data). Network required.
 *
 *   bun scripts/refresh-attack.ts            # latest Enterprise release
 *   bun scripts/refresh-attack.ts 19.2       # a specific release
 *
 * Output: every non-revoked, non-deprecated Enterprise technique and sub-technique with its
 * ATT&CK tactic phase names and URL, sorted by ID. Zero dependencies.
 */
import { join } from "node:path";

const BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/";
const OUT = join(import.meta.dir, "..", "skills", "standards", "references", "attack-techniques.json");

type Version = { version: string; modified: string; url: string };
type Collection = { name: string; versions: Version[] };

const index = (await (await fetch(BASE + "index.json")).json()) as { collections: Collection[] };
const enterprise = index.collections.find((c) => /enterprise/i.test(c.name));
if (!enterprise) throw new Error("Enterprise collection not found in index.json");

const wanted = process.argv[2];
const versions = [...enterprise.versions].sort((a, b) => (a.modified < b.modified ? 1 : -1));
const pick = wanted ? versions.find((v) => v.version === wanted) : versions[0];
if (!pick) throw new Error(`version ${wanted} not in index`);

const url = pick.url.replace(/^https:\/\/raw\.githubusercontent\.com\/mitre-attack\/attack-stix-data\/master\//, BASE);
console.error(`fetching Enterprise ATT&CK ${pick.version} (${pick.modified})`);
const bundle = (await (await fetch(url)).json()) as { objects: any[] };

type Technique = { id: string; name: string; tactics: string[]; url: string | undefined };
const techniques: Technique[] = bundle.objects
  .filter((o) => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated)
  .map((o) => {
    const ext = (o.external_references ?? []).find((r: any) => r.source_name === "mitre-attack");
    return {
      id: ext?.external_id as string,
      name: o.name as string,
      tactics: (o.kill_chain_phases ?? [])
        .filter((k: any) => k.kill_chain_name === "mitre-attack")
        .map((k: any) => k.phase_name as string),
      url: ext?.url as string | undefined,
    };
  })
  .filter((t) => typeof t.id === "string")
  .sort((a, b) => a.id.localeCompare(b.id));

const out = {
  schema: "casa.attack-techniques/v1",
  source: "MITRE ATT&CK Enterprise (STIX 2.1), github.com/mitre-attack/attack-stix-data",
  attack_version: pick.version,
  retrieved: new Date().toISOString().slice(0, 10),
  count: techniques.length,
  techniques,
};
await Bun.write(OUT, JSON.stringify(out, null, 1) + "\n");
console.error(`wrote ${techniques.length} techniques to ${OUT}`);
