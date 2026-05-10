import os
import json
import requests

from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "openai/gpt-oss-20b:free"


def ask_ai(prompt):

    response = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an elite cybersecurity remediation expert. "
                        "Generate concise, accurate, production-ready fixes."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 500
        },
        timeout=45
    )

    data = response.json()

    return data["choices"][0]["message"]["content"]


def build_prompt(title, description, severity):

    return f"""
A vulnerability was detected.

Title:
{title}

Description:
{description}

Severity:
{severity}

Generate JSON only.

Format:

{{
  "title": "...",
  "explanation": "...",
  "impact": "...",
  "commands": [
    "command 1",
    "command 2"
  ],
  "config": "optional config"
}}

Rules:
- Keep explanations short
- Commands must be real
- Generate nginx/apache/ssh configs if needed
- No markdown
- JSON only
"""


def parse_ai_response(raw, title):

    clean = raw.strip()

    if clean.startswith("```json"):
        clean = (
            clean
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

    try:
        return json.loads(clean)

    except Exception as e:
        return {
            "title": title,
            "explanation": clean,
            "impact": str(e),
            "commands": [],
            "config": ""
        }


def generate_remediation(findings):

    remediations = []

    for finding in findings:

        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "INFO")

        prompt = build_prompt(
            title,
            description,
            severity
        )

        try:

            raw = ask_ai(prompt)

            parsed = parse_ai_response(raw, title)

            remediations.append(parsed)

        except Exception as e:

            remediations.append({
                "title": title,
                "explanation": "AI remediation generation failed.",
                "impact": str(e),
                "commands": [],
                "config": ""
            })

    return remediations


def generate_single_remediation(data):

    title = data.get("title", "")
    description = data.get("description", "")
    severity = data.get("severity", "INFO")

    prompt = build_prompt(
        title,
        description,
        severity
    )

    try:

        raw = ask_ai(prompt)

        return parse_ai_response(raw, title)

    except Exception as e:

        return {
            "title": title,
            "explanation": "AI remediation generation failed.",
            "impact": str(e),
            "commands": [],
            "config": ""
        }
