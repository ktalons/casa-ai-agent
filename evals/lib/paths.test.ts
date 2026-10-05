import { test, expect } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Skills and agents load into any project where the plugin is installed, so every path into the
// plugin's own tree must go through ${CLAUDE_PLUGIN_ROOT}, which Claude Code substitutes when it
// loads the Markdown. A bare plugin-relative path only works from the CASA checkout itself.
const ROOT = join(import.meta.dir, "..", "..");
const ROOT_VAR = "${CLAUDE_PLUGIN_ROOT}";
const files = [
  ...readdirSync(join(ROOT, "skills")).map((d) => join("skills", d, "SKILL.md")),
  ...readdirSync(join(ROOT, "agents")).filter((f) => f.endsWith(".md")).map((f) => join("agents", f)),
  join("skills", "investigate", "references", "task-template.md"),
];
const INTERNAL = /(^|[^/\w}])(?:intake\/fixtures|intake\/Validate\.ts|evals\/(?:Lint|Grade|RunFull)\.ts|evals\/samples|skills\/(?:standards|investigate)\/references|skills\/standards\/SKILL\.md|references\/(?:workflows|task-template|brief-template|attack-techniques|csf-2\.0|nist-citations|lessons))\b/g;

for (const f of files) {
  test(`${f}: plugin-internal paths are anchored to ${ROOT_VAR}`, () => {
    const text = readFileSync(join(ROOT, f), "utf8");
    const bare: string[] = [];
    for (const m of text.matchAll(INTERNAL)) {
      const before = text.slice(Math.max(0, m.index! - ROOT_VAR.length - 20), m.index! + m[1].length);
      if (!before.includes(ROOT_VAR)) bare.push(m[0].trim());
    }
    expect(bare).toEqual([]);
  });
}

test("the allow lists cover the plugin-root forms of the validator, lint and grader", () => {
  for (const f of [".claude/settings.json", "docs/settings.recommended.json"]) {
    const allow: string[] = JSON.parse(readFileSync(join(ROOT, f), "utf8")).permissions.allow;
    for (const rule of ["Bash(bun */intake/Validate.ts *)", "Bash(bun */evals/Lint.ts *)", "Bash(bun */evals/Grade.ts *)"]) expect(allow).toContain(rule);
  }
});
