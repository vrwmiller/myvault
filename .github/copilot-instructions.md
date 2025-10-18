# Copilot Instructions

## Purpose
This repository contains source code used to evaluate and test GitHub, GitHub Copilot, and OpenAI capabilities for code generation, natural language processing, and AI-assisted development. It is primarily a learning tool and a sandbox for experimenting with AI-driven coding workflows. It's acceptable to increase complexity and add features as needed to explore various use cases.

## Secrets & configuration
- Never hard-code API keys or credentials in code or examples.
- Use environment variables for credentials (example names below):
  - OPENAI_API_KEY
  - OPENAI_API_BASE (only if using self-hosted/alternate base)
  - OPENAI_API_TYPE / OPENAI_API_VERSION (if using Azure or special configs)
- Prefer a single configuration object to hold API-related settings (model, temperature, timeout, max_tokens, streaming flag).
- Ensure callers can override configuration in a single place (e.g., with a Config dataclass).

## Project Conventions
- Python scripts use the `.py` extension and follow a 4 whitespace indentation style.
- Emojis aren't used in code files, documentation, or comments.
- Code is commented using docstrings and inline comments where necessary.
- The project uses a `requirements.txt` file to manage Python dependencies.
- The main script for user interaction is `askgpt.py`.

## Key Workflows
* Run locally:
    ```bash
    python3 -m venv venv && source venv/bin/activate
    python3 -m pip install --upgrade pip
    pip3 install -r requirements.txt
    ```

## Rate limits & token budgeting
- Always be mindful of model token limits (both prompt and response).
- Provide utilities to estimate token usage and to truncate/stream content if near budget.
- Where possible, reuse contexts or compress prompt state rather than resending full history every call.

## Security & privacy
- Never write or store API keys in the repository, logs, or error messages.
- When logging user content or responses, mask or redact PII before persisting logs.
- For persisted chat logs, use a configurable retention policy and encryption at rest if applicable.
- If using third-party hosting or a proxy, clearly document how requests are routed and who can access logs.

## Testing & mocks
- All OpenAI calls must be isolated behind an interface or wrapper so unit tests can mock them.
- Provide test fixtures for:
  - Mocked successful responses
  - Mocked streaming generator responses
  - Mocked rate-limit / error responses
- Write integration tests that are opt-in (skip by default) and require a real API key set via CI secrets only when explicitly enabled.
- Use deterministic seeds for tests that involve randomness (e.g., temperature-based sampling) or mock sampling behavior.
