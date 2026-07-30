#!/usr/bin/env bun
/**
 * StartupGreeting.hook.ts - Session start banner + optional voice greeting (SessionStart)
 *
 * PURPOSE:
 * Prints a compact CASA banner confirming the environment is initialized, and
 * fires an optional non-blocking voice greeting when a voice ID is configured.
 *
 * TRIGGER: SessionStart
 *
 * ERROR HANDLING:
 * - Missing or malformed settings.json degrades to defaults via getIdentity();
 *   the banner is cosmetic, so this hook always exits 0.
 */

import { getIdentity, getPrincipal } from './lib/identity';

(async () => {
  try {
    // Subagent sessions stay silent.
    if (process.env.CLAUDE_AGENT_TYPE !== undefined) {
      process.exit(0);
    }

    const identity = getIdentity();
    const principal = getPrincipal();

    const name = identity.displayName || identity.name;
    console.log(`${name} — ${identity.fullName}`);
    console.log(`Analyst: ${principal.name} · TZ: ${principal.timezone}`);
    console.log('Workflows: auth-anomaly · beaconing · exfiltration · lateral-movement · intake-triage');

    // Voice greeting is opt-in: no configured voice ID means no request at all.
    if (identity.voiceId) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000);

      await fetch('http://localhost:8888/notify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          message: `${identity.name} here, ready to go.`,
          title: 'Session Start',
          voice_enabled: true,
          voice_id: identity.voiceId,
          voice_settings: identity.voice
            ? {
                stability: identity.voice.stability ?? 0.5,
                similarity_boost: identity.voice.similarity_boost ?? 0.75,
                style: identity.voice.style ?? 0.0,
                speed: identity.voice.speed ?? 1.0,
                use_speaker_boost: identity.voice.use_speaker_boost ?? true,
              }
            : undefined,
        }),
      })
        .catch(() => {}) // Silent fail if the voice server is not running
        .finally(() => clearTimeout(timeoutId));
    }
  } catch (error) {
    console.error('StartupGreeting: banner failed (non-fatal)', error);
  }
  process.exit(0);
})();
