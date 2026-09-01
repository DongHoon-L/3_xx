#!/usr/bin/env bash
# Local chatbot server: llama.cpp (llama.app) with the cached Qwen3 27B model.
# Install once (from Windows):
#   wsl.exe -- bash -c "cp /mnt/c/Users/shapd/Documents/prism/ch3/3_xx/scripts/wsl-chatbot.sh ~/chatbot.sh && sed -i 's/\r$//' ~/chatbot.sh && chmod +x ~/chatbot.sh"
# Use (from Windows or inside WSL):
#   wsl.exe -- ~/chatbot.sh start     # background, waits until the model is loaded
#   wsl.exe -- ~/chatbot.sh status | stop | logs
#   wsl.exe -- ~/chatbot.sh run       # foreground (Ctrl+C stops)
# Then: web chat UI  http://localhost:8080   |  OpenAI-compatible API  http://localhost:8080/v1
set -euo pipefail

LLAMA="$HOME/.llama-app/llama"
MODEL="${CHATBOT_MODEL:-huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:Q4_K_XL}"
PORT="${CHATBOT_PORT:-8080}"
HOST="${CHATBOT_HOST:-0.0.0.0}"     # 0.0.0.0 = reachable from Windows via localhost (WSL2 port forwarding)
CTX="${CHATBOT_CTX:-8192}"          # context tokens; raise if VRAM allows
PIDFILE="$HOME/.chatbot.pid"
LOG="$HOME/chatbot.log"
ARGS=(serve -hf "$MODEL" --host "$HOST" --port "$PORT" -c "$CTX" --alias local)

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
healthy() { curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; }

case "${1:-start}" in
  run)
    exec "$LLAMA" "${ARGS[@]}"
    ;;
  start)
    if is_running; then
      echo "already running (pid $(cat "$PIDFILE")) — http://localhost:$PORT"
      exit 0
    fi
    setsid nohup "$LLAMA" "${ARGS[@]}" >"$LOG" 2>&1 < /dev/null &
    echo $! >"$PIDFILE"
    echo "starting pid $! (model load takes a few minutes) — log: $LOG"
    for _ in $(seq 1 180); do
      if healthy; then
        echo "ready: web UI http://localhost:$PORT  |  API http://localhost:$PORT/v1  (model alias: local)"
        exit 0
      fi
      if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "server exited — last log lines:"; tail -20 "$LOG"; rm -f "$PIDFILE"; exit 1
      fi
      sleep 2
    done
    echo "still loading after 6 minutes — check: $0 logs"; exit 1
    ;;
  stop)
    if is_running; then kill "$(cat "$PIDFILE")"; rm -f "$PIDFILE"; echo "stopped"; else echo "not running"; fi
    ;;
  status)
    if is_running; then
      echo "running (pid $(cat "$PIDFILE"))"; healthy && echo "health: ok — http://localhost:$PORT" || echo "health: not ready yet"
    else
      echo "not running"
    fi
    ;;
  logs)
    tail -n 40 -f "$LOG"
    ;;
  *)
    echo "usage: $0 start|stop|status|logs|run"; exit 2
    ;;
esac
