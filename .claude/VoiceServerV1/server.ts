/**
 * PAI Voice Server V1 — ElevenLabs TTS
 *
 * Handles voice notifications via ElevenLabs API.
 * Reads ELEVENLABS_API_KEY from ~/.claude/.env or environment.
 *
 * Usage:  cd ~/.claude/VoiceServerV1 && bun run server.ts
 * Port:   8888
 */

import { serve } from "bun";
import { existsSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir, tmpdir } from "os";
import { spawnSync } from "child_process";

// ── Environment ─────────────────────────────────────────────────────────────

function loadDotEnv(): void {
  const envPath = join(homedir(), ".claude", ".env");
  if (!existsSync(envPath)) return;
  const lines = readFileSync(envPath, "utf-8").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx < 1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, "");
    if (key && !process.env[key]) process.env[key] = value;
  }
}

loadDotEnv();

const PORT = parseInt(process.env.PORT || "8888");
const ELEVENLABS_API_KEY = process.env.ELEVENLABS_API_KEY || "";
const DEFAULT_VOICE_ID =
  process.env.PAI_VOICE_ID || "21m00Tcm4TlvDq8ikWAM";

// ── Types ────────────────────────────────────────────────────────────────────

interface VoiceSettings {
  stability?: number;
  similarity_boost?: number;
  style?: number;
  speed?: number;
  use_speaker_boost?: boolean;
}

interface NotifyRequest {
  message: string;
  voice_id?: string;
  voice_enabled?: boolean;
  title?: string;
  voice_settings?: VoiceSettings;
}

// ── ElevenLabs TTS ──────────────────────────────────────────────────────────

async function synthesizeAndPlay(
  text: string,
  voiceId: string,
  voiceSettings?: VoiceSettings
): Promise<void> {
  if (!ELEVENLABS_API_KEY) {
    throw new Error("ELEVENLABS_API_KEY not set — check ~/.claude/.env");
  }

  const settings: VoiceSettings = {
    stability: 0.35,
    similarity_boost: 0.80,
    style: 0.90,
    speed: 1.1,
    use_speaker_boost: true,
    ...voiceSettings,
  };

  const resp = await fetch(
    `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}/stream`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY,
      },
      body: JSON.stringify({
        text,
        model_id: "eleven_turbo_v2_5",
        voice_settings: settings,
      }),
    }
  );

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`ElevenLabs error ${resp.status}: ${err}`);
  }

  const audioData = new Uint8Array(await resp.arrayBuffer());
  const tmpFile = join(tmpdir(), `pai-voice-${Date.now()}.mp3`);

  writeFileSync(tmpFile, audioData);

  // macOS: afplay; Linux fallback: mpg123
  const player = existsSync("/usr/bin/afplay") ? "afplay" : "mpg123";
  spawnSync(player, [tmpFile], { stdio: "ignore" });

  try {
    unlinkSync(tmpFile);
  } catch {
    // ignore cleanup errors
  }
}

// ── HTTP Server ──────────────────────────────────────────────────────────────

const server = serve({
  port: PORT,
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // Health check
    if (url.pathname === "/health" && req.method === "GET") {
      return Response.json({
        status: "healthy",
        engine: "elevenlabs",
        model: "eleven_turbo_v2_5",
        api_key_set: !!ELEVENLABS_API_KEY,
        default_voice_id: DEFAULT_VOICE_ID,
        port: PORT,
      });
    }

    // Voice notification
    if (url.pathname === "/notify" && req.method === "POST") {
      let body: NotifyRequest;
      try {
        body = (await req.json()) as NotifyRequest;
      } catch {
        return Response.json({ error: "Invalid JSON" }, { status: 400 });
      }

      if (!body.message) {
        return Response.json({ error: "message is required" }, { status: 400 });
      }

      if (body.voice_enabled === false) {
        return Response.json({
          status: "success",
          message: "Notification received (voice disabled)",
        });
      }

      try {
        const voiceId = body.voice_id || DEFAULT_VOICE_ID;
        await synthesizeAndPlay(body.message, voiceId, body.voice_settings);
        return Response.json({ status: "success", message: "Notification sent", engine: "elevenlabs" });
      } catch (err) {
        console.error("Voice synthesis failed:", err);
        return Response.json(
          { status: "error", error: String(err) },
          { status: 500 }
        );
      }
    }

    return new Response("Not found", { status: 404 });
  },
});

console.log(`\nPAI Voice Server V1 (ElevenLabs) — port ${PORT}`);
console.log(`API Key: ${ELEVENLABS_API_KEY ? "SET ✓" : "NOT SET ✗ — check ~/.claude/.env"}`);
console.log(`Default Voice ID: ${DEFAULT_VOICE_ID}`);
console.log(`Health: http://localhost:${PORT}/health\n`);
