# Secret Sweep

Run `npm run build:offline` and open `dist/secret-sweep.html` in a browser for an offline scan. Choose the repository root to scan its current files, or use **Try sample scan** to see synthetic findings. Reports contain locations and rule names. The scanner does not upload files or validate tokens against providers.

## Git commands

Requires Git and Node.js 18 or later. Keep this checkout in a stable folder and run these commands from the repository you want to scan. Replace the example path with the actual path to the CLI.

```powershell
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" staged
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" install-hook
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" history
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" history --json
```

- **staged** reads the Git index and scans added or changed lines. High findings block the commit. Medium findings are reported.
- **install-hook** writes Git's pre-commit hook and refuses to overwrite an existing hook. If your repo already has one, add the staged command to that hook and propagate its exit status. Keep the CLI in place, or update the hook path if you move it.
- **history** scans committed file versions reachable from local refs and HEAD, including files deleted later. It scans each distinct path and blob once and reports the first commit it scanned for that pair. Shallow clones are limited to available commits. Large histories can take time.
- Exit codes are **0** for no High findings, **1** for High findings, and **2** for an operational error. The scan skips binary files, selected dependency and build folders, and files larger than 2 MB.

## Allowlist

Save a `.secretsweep.json` file in the repository root. Paths are exact, case-sensitive repository-relative paths with forward slashes. Use the rule name shown in the report.

```json
{
  "allow": [
    { "path": "tests/fixtures/demo.js", "rule": "GitHub token" }
  ]
}
```

Stage the config to apply it to the pre-commit scan. The history command uses the current root config. The website reads the selected folder's root config or a file explicitly loaded under **Allowlist settings**. An entry suppresses every finding for that rule in that file, so keep entries specific to known fixtures.



## Development and deployment

Use Node.js 22 or newer. Run `npm test` for the scanner, offline dashboard and real Git hook tests. The website entry point is `public/index.html`, and the CLI shares `public/scanner.js` with it.

Import the GitHub repository into Vercel and use the repository root as the project root. The checked-in `vercel.json` selects the Other preset and serves `public/` directly. No build, environment variables, API routes or server are required. Verify the deployment by opening the site and selecting **Try sample scan**. It should show three synthetic findings.
