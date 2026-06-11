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

## Authentication (do this before exposing it publicly)

The server enforces an API key when `SAP_API_KEY` is set in its environment;
unset, the endpoints are open (local/demo only). Set it on your host:

```bash
docker run -p 8765:8765 -e SAP_API_KEY="$(openssl rand -hex 24)" sap-scanner
```

Then in the Custom GPT Action, choose **Authentication → API Key → Custom header
`X-API-Key`** and paste the same value (the spec already declares this scheme).

## Custom domain — api.mirawyn.com

[`render.yaml`](../../render.yaml) pins `domains: [api.mirawyn.com]`, so Render
requests the TLS certificate automatically once DNS resolves:

1. Render → the service → **Settings → Custom Domains** shows the exact CNAME
   target (e.g. `secure-ai-pipeline-scanner.onrender.com`).
2. In Squarespace (DNS for mirawyn.com): **Settings → Domains → mirawyn.com →
   DNS Settings → Add record** — Type `CNAME`, Host `api`, Data = the Render
   target from step 1. (Full walkthrough: [`docs/domain-setup.md`](../../docs/domain-setup.md).)
3. After propagation, `https://api.mirawyn.com/health` → `{"status":"ok",...}`.

Until the CNAME exists, the service still answers on its `*.onrender.com` URL —
point `servers[0].url` there temporarily if you want to test the GPT first.

## Wire it into the Custom GPT

1. [`openapi.yaml`](openapi.yaml) already points `servers[0].url` at
   `https://api.mirawyn.com`.
2. In ChatGPT → **Create a GPT → Configure → Actions → Create new action**, paste the
   contents of `openapi.yaml`.
3. Paste [`GPT_INSTRUCTIONS.md`](GPT_INSTRUCTIONS.md) into the GPT's **Instructions** box.
4. Test: share a code snippet and confirm the GPT calls `sastScan` / `fullScan`.

> The endpoints are read-only (`x-openai-isConsequential: false`), so the GPT can call them
> without a confirmation prompt.
