#!/usr/bin/env bash
set -euo pipefail

# Integration smoke test against a running stack (run `make start` first).
# Tests 4-5 use the OpenAI Python SDK; point PYTHON_BIN at an interpreter that has `openai` installed.

echo "=== Test 1: health through Flask directly ==="
curl -sS http://127.0.0.1:8080/health | python3 -m json.tool

echo
echo "=== Test 2: model discovery through Nginx ==="
curl -sS http://127.0.0.1:8081/v1/models \
  -H "Authorization: Bearer private-portfolio-token" | python3 -m json.tool

echo
echo "=== Test 3: chat through Nginx with curl, model=strategy ==="
curl -sS http://127.0.0.1:8081/v1/chat/completions \
  -H "Authorization: Bearer private-portfolio-token" \
  -H "Content-Type: application/json" \
  -d '{
    "model":"strategy",
    "messages":[{"role":"user","content":"Say OK."}],
    "max_tokens":20
  }' | python3 -m json.tool

echo
echo "=== Test 4: Python OpenAI SDK, model=strategy ==="
"${PYTHON_BIN:-python3}" - <<'PY'
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8081/v1",
    api_key="private-portfolio-token",
)

r = client.chat.completions.create(
    model="strategy",
    messages=[{"role":"user","content":"Say OK."}],
    max_tokens=20,
)

print("MODEL:", r.model)
print("TEXT:", r.choices[0].message.content)
PY

echo
echo "=== Test 5: Python OpenAI SDK with tool-shaped request ==="
"${PYTHON_BIN:-python3}" - <<'PY'
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8081/v1",
    api_key="private-portfolio-token",
)

r = client.chat.completions.create(
    model="strategy",
    messages=[
        {"role":"system","content":"You are a local agent. Answer briefly."},
        {"role":"user","content":"Say OK."}
    ],
    tools=[
        {
            "type": "function",
            "function": {
                "name": "noop",
                "description": "No operation.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ],
    tool_choice="auto",
    max_tokens=20,
)

print("TEXT:", r.choices[0].message.content)
PY

echo
echo "All endpoint tests completed."
