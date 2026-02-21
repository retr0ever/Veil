import httpx
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

CRUSOE_API_URL = os.getenv("CRUSOE_API_URL", "https://inference.crusoe.ai/v1")
CRUSOE_API_KEY = os.getenv("CRUSOE_API_KEY", "")
CRUSOE_MODEL = os.getenv("CRUSOE_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct")


async def classify(user_message: str, system_prompt: str) -> dict:
    start = time.time()
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"{CRUSOE_API_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {CRUSOE_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": CRUSOE_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "temperature": 0.0,
                "max_tokens": 200,
            },
        )
        elapsed_ms = (time.time() - start) * 1000

        if resp.status_code != 200:
            return {
                "classification": "SUSPICIOUS",
                "confidence": 0.5,
                "reason": f"Crusoe API error: {resp.status_code}",
                "classifier": "crusoe",
                "response_time_ms": elapsed_ms,
            }

        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            # try to extract JSON from response
            start_idx = content.find("{")
            end_idx = content.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                result = json.loads(content[start_idx:end_idx])
            else:
                result = {
                    "classification": "SUSPICIOUS",
                    "confidence": 0.5,
                    "reason": "Failed to parse classifier response",
                }

        result["classifier"] = "crusoe"
        result["response_time_ms"] = elapsed_ms
        return result
