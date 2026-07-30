#!/usr/bin/env bun
/**
 * StopOrchestrator.hook.ts - Single Entry Point for Stop Hooks
 *
 * PURPOSE:
 * Orchestrates the Stop event handlers by reading and parsing the transcript
 * ONCE, then distributing the parsed data to isolated handlers.
 *
 * TRIGGER: Stop (fires after Claude generates a response)
 *
 * INPUT (stdin JSON):
 * - session_id: Current session identifier
 * - transcript_path: Path to the JSONL transcript file
 * - hook_event_name: "Stop"
 *
 * HANDLERS (in hooks/handlers/):
 * - VoiceNotification.ts: Extracts the voice line, sends to the voice server
 * - ResponseCapture.ts: Updates current-work state under MEMORY/
 *
 * ERROR HANDLING:
 * - Missing transcript: exits 0
 * - Parse failures: logged to stderr, exits 0
 * - Handler failures: isolated via Promise.allSettled
 */

import { parseTranscript, type ParsedTranscript } from './lib/TranscriptParser';
import { handleVoice } from './handlers/VoiceNotification';
import { handleCapture } from './handlers/ResponseCapture';

interface HookInput {
  session_id: string;
  transcript_path: string;
  hook_event_name: string;
}

const STDIN_TIMEOUT_MS = 2000;

async function readStdin(): Promise<HookInput | null> {
  const reader = Bun.stdin.stream().getReader();
  const decoder = new TextDecoder();
  let input = '';

  try {
    const timeoutPromise = new Promise<'timeout'>((resolve) => {
      setTimeout(() => resolve('timeout'), STDIN_TIMEOUT_MS);
    });

    const readPromise = (async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        input += decoder.decode(value, { stream: true });
      }
      return 'done' as const;
    })();

    const winner = await Promise.race([readPromise, timeoutPromise]);
    if (winner === 'timeout') {
      // Stop pulling; parse whatever arrived before the deadline.
      await reader.cancel().catch(() => {});
    }

    if (input.trim()) {
      return JSON.parse(input) as HookInput;
    }
  } catch (error) {
    console.error('[StopOrchestrator] Error reading stdin:', error);
  }
  return null;
}

async function main() {
  const hookInput = await readStdin();

  if (!hookInput || !hookInput.transcript_path) {
    console.error('[StopOrchestrator] No transcript path provided');
    process.exit(0);
  }

  // SINGLE READ, SINGLE PARSE — a malformed transcript must never leave the
  // Stop event hanging on an uncaught throw.
  let parsed: ParsedTranscript;
  try {
    parsed = parseTranscript(hookInput.transcript_path);
  } catch (error) {
    console.error('[StopOrchestrator] Failed to parse transcript:', error);
    process.exit(0);
  }

  const results = await Promise.allSettled([
    handleVoice(parsed, hookInput.session_id),
    handleCapture(parsed, hookInput),
  ]);

  const handlerNames = ['Voice', 'Capture'];
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      console.error(`[StopOrchestrator] ${handlerNames[index]} handler failed:`, result.reason);
    }
  });

  process.exit(0);
}

main().catch((error) => {
  console.error('[StopOrchestrator] Fatal error:', error);
  process.exit(0);
});
