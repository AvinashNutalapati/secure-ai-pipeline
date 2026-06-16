# Releasing

This repo ships through several channels from one codebase. Keep the version in
sync across all of them, then publish per channel.

## Version locations (must all match)

When cutting a release, bump the version in every file below to the same value:

- `package.json` — the npm CLI (`npx secure-ai-pipeline`)
- `extensions/vscode/package.json` — the VS Code / Cursor extension
- `setup.py` — the pip-installable MCP server (`sap-mcp`)
- `extensions/claude_mcp/server.py` — the REST API (`version=`)
- `extensions/claude_mcp/mcp_manifest.json` — the MCP tool manifest
- `extensions/claude_mcp/dxt/manifest.json` uses the `__VERSION__` token and is
  filled in at build time by `extensions/claude_mcp/dxt/build_dxt.py` — no manual edit

Then tag and move the `@v3` major tag:

```bash
git tag v3.X.Y
git push origin v3.X.Y
git tag -f v3            # the floating major tag the README/Action recommend
git push -f origin v3
```

## npm — `npx secure-ai-pipeline` (the only outstanding blocker)

The package is **publish-ready**: `npm pack` bundles every runtime file (verified by
`tests/test_cli_e2e.py`), the bin works from a clean install, and the name
`secure-ai-pipeline` is **unclaimed** on the registry. The *only* thing standing
between the current state and a working `npx secure-ai-pipeline` is the publish
step, which needs npm credentials:

```bash
# 1. Authenticate (interactive — opens a browser / prompts for OTP).
npm login

# 2. Dry-run to eyeball the contents (prepublishOnly runs the bin smoke test).
npm publish --dry-run

# 3. Publish (unscoped package → public by default).
npm publish
```

After step 3, `npx secure-ai-pipeline@latest scan .` works for anyone. Until then,
the README's `npx` commands are documented-but-not-yet-installable — users can run
the CLI from a clone (`node cli/init.js scan .`) in the meantime.

> The package has **zero npm dependencies**, so `npm install` of the published
> tarball needs no network beyond fetching the package itself.

## GitHub Action — `uses: AvinashNutalapati/secure-ai-pipeline@v3`

No publish step beyond pushing the tag (see above). The Action is consumed
straight from the tagged repo. To list it on the Marketplace, use GitHub's
**Draft a release → Publish this Action to the Marketplace** flow on a tag.

## VS Code / Cursor extension

Published under the `AvinashNutalapati1` Marketplace publisher:

```bash
cd extensions/vscode
npm run compile      # or: npx vsce package   to produce a .vsix locally
npx vsce publish     # needs a Marketplace PAT (vsce login AvinashNutalapati1)
```

## MCP server (pip / PyPI)

```bash
python -m build           # builds the sdist + wheel from setup.py
twine upload dist/*       # needs PyPI credentials
```

Until it's on PyPI, install from git:
`pipx install git+https://github.com/AvinashNutalapati/secure-ai-pipeline.git`

## OpenAI Custom GPT Action

Backed by the REST server at `https://api.mirawyn.com` (DNS/deploy is the pending
piece — see `docs/domain-setup.md`). Self-hosting instructions:
`extensions/openai-gpt/DEPLOY.md`.
