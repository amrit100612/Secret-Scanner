---
name: secret-sweep
description: Scan a local Git repository with Secret Sweep for hardcoded API keys, tokens, passwords, and private keys. Use for a staged-change scan before committing, a local Git history scan, or an explicit request to install Secret Sweep's pre-commit hook.
---

# Secret Sweep

Run the Secret Sweep CLI from the Git repository the user wants to check. Use an absolute path to `cli/git-sweep.cjs` in a trusted checkout of [Secret Sweep](https://github.com/amrit100612/Secret-Scanner-). A standalone skill install includes these instructions. If the CLI is unavailable, explain that it needs a separate checkout and obtain it when the user's request authorizes setup. Use Git and Node.js 22 or newer.

## Choose the scan

- For a pre-commit check, run `node "<absolute-cli-path>" staged --json`. It checks added or changed lines in the Git index. If nothing is staged, state that and leave the index alone.
- For a history check, run `node "<absolute-cli-path>" history --json`. It checks locally available commits. A shallow clone limits coverage.
- For a scan of current files, including files outside the Git index, use the folder scan on the [Secret Sweep dashboard](https://secret-scanner-git.vercel.app/). The browser reads the files locally.
- Install the hook only when asked. Run `node "<absolute-cli-path>" install-hook` from the target repo and keep the CLI checkout in place. If the repo already has a hook, report the conflict and preserve the existing hook.

## Report the result

Exit code `0` means the scan found no High findings. Medium findings may still appear in the JSON. Exit code `1` means High findings were reported, and `2` means the operation failed.

Report the file, line, rule, severity, and commit when available. Keep matched secret values out of output. Describe matches as potential exposures and note skipped files or shallow history when relevant. Use exact path-and-rule entries in `.secretsweep.json` for known test fixtures only when the user asks to suppress them.
