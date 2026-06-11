# Domain setup — mirawyn.com

The product uses one custom hostname today, with room to grow:

| Hostname | Purpose | Points at | Status |
|---|---|---|---|
| `api.mirawyn.com` | Scanner REST API (GPT Action backend, `/health`, `/full_scan`, …) | Render web service | **needs the DNS record below** |
| `mirawyn.com` / `www` | Product page (future) | Squarespace site / GitHub Pages | optional, later |

## 1. The one record needed now (Squarespace)

DNS for `mirawyn.com` is managed in Squarespace. Add a single CNAME:

1. Squarespace → **Settings → Domains → mirawyn.com → DNS Settings** (sometimes
   shown as *Advanced DNS Settings*).
2. **Add record**:
   - **Type:** `CNAME`
   - **Host:** `api`
   - **Data / Target:** the Render CNAME target shown in Render → service
     `secure-ai-pipeline-scanner` → **Settings → Custom Domains** (it looks like
     `secure-ai-pipeline-scanner.onrender.com`).
3. Save. Propagation is usually minutes, occasionally a few hours.

Render detects the record, verifies the domain, and issues the TLS certificate
automatically (`render.yaml` already declares `domains: [api.mirawyn.com]`).

**Verify:** `curl https://api.mirawyn.com/health` → `{"status": "ok", ...}`.

> Squarespace reserves the root domain (`@`) and `www` for its own site
> hosting unless you change nameservers — that's fine: the API lives on the
> `api` subdomain, which Squarespace lets you CNAME freely.

## 2. Optional, later

- **Product page** — keep `mirawyn.com`/`www` on Squarespace and build the page
  there, or CNAME `www` → `avinashnutalapati.github.io` for a GitHub Pages
  site (add a `CNAME` file to the Pages repo if so).
- **Docs site** — `docs.mirawyn.com` can CNAME the same way when there's a
  docs build to host.

## Where the domain is referenced in this repo

- `extensions/openai-gpt/openapi.yaml` → `servers[0].url: https://api.mirawyn.com`
- `render.yaml` → `domains: [api.mirawyn.com]`
- `README.md`, `extensions/claude_mcp/README.md`, `extensions/openai-gpt/DEPLOY.md`
- VS Code extension `homepage` and MCP manifest `homepage` → `https://mirawyn.com`

If the API hostname ever changes, update `openapi.yaml` and re-paste it into the
Custom GPT's Action (GPTs snapshot the spec; they don't re-fetch it).
