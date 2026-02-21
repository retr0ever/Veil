from anthropic import AsyncAnthropicBedrock
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")
BEDROCK_MODEL = os.getenv("BEDROCK_MODEL", "global.anthropic.claude-sonnet-4-5-20250929-v1:0")


async def classify(user_message: str, system_prompt: str) -> dict:
    start = time.time()
    client = AsyncAnthropicBedrock(aws_region=AWS_REGION)

    try:
        response = await client.messages.create(
            model=BEDROCK_MODEL,
            max_tokens=300,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        elapsed_ms = (time.time() - start) * 1000
        content = response.content[0].text.strip()

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            start_idx = content.find("{")
            end_idx = content.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                result = json.loads(content[start_idx:end_idx])
            else:
                result = {
                    "classification": "SUSPICIOUS",
                    "confidence": 0.5,
                    "attack_type": "none",
                    "reason": "Failed to parse classifier response",
                }

        result["classifier"] = "claude"
        result["response_time_ms"] = elapsed_ms
        return result

    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        return {
            "classification": "SUSPICIOUS",
            "confidence": 0.5,
            "attack_type": "none",
            "reason": f"Claude API error: {str(e)}",
            "classifier": "claude",
            "response_time_ms": elapsed_ms,
        }
