# Deploying the GPT Action scanner

The OpenAI Custom GPT Action needs a **public HTTPS endpoint** to call. That endpoint is the
FastAPI REST server in `extensions/claude_mcp/server.py`, packaged by the repo-root
[`Dockerfile`](../../Dockerfile). Two ways to host it:

## Option A — Render (one click, uses `render.yaml`)

1. Push this repo to GitHub (already done).
2. In Render → **New → Blueprint** → pick this repo. Render reads the root
   [`render.yaml`](../../render.yaml) and provisions a Docker web service.
3. Wait for the deploy, then copy the service URL, e.g. `https://secure-ai-pipeline-scanner.onrender.com`.
4. Health check: open `<url>/health` → `{"status":"ok",...}`.

## Option B — Any Docker host (Fly.io, Cloud Run, a VPS, …)

```bash
docker build -t sap-scanner .
docker run -p 8765:8765 sap-scanner
curl http://localhost:8765/health     # -> {"status":"ok",...}
```

Then put it behind HTTPS (the platform's TLS, or a reverse proxy).

## Wire it into the Custom GPT

1. Edit [`openapi.yaml`](openapi.yaml) → set `servers[0].url` to your deployed HTTPS URL.
2. In ChatGPT → **Create a GPT → Configure → Actions → Create new action**, paste the
   contents of `openapi.yaml`.
3. Paste [`GPT_INSTRUCTIONS.md`](GPT_INSTRUCTIONS.md) into the GPT's **Instructions** box.
4. Test: share a code snippet and confirm the GPT calls `sastScan` / `fullScan`.

> The endpoints are read-only (`x-openai-isConsequential: false`), so the GPT can call them
> without a confirmation prompt.
