#!/bin/bash
# Start PAI Voice Server V1 (ElevenLabs)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PORT=8888

# Check if already running
if lsof -i :$PORT > /dev/null 2>&1; then
    echo "Voice server already running on port $PORT"
    echo "Use: kill \$(lsof -t -i :$PORT) to stop it"
    exit 0
fi

echo "Starting PAI Voice Server V1 (ElevenLabs) on port $PORT..."
cd "$SCRIPT_DIR"
bun run server.ts
