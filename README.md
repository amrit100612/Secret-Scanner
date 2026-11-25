# Secret Sweep

**Catch secrets before you commit them.**

Imagine you add an API key to a file while testing your app. A few days later, you forget it is there and get ready to push your code to GitHub. Secret Sweep can point you to the file and line before that key gets shared.

It looks for common API keys, access tokens, private keys, and passwords in places like `.env` files. A finding tells you **where to look** and **what the scanner found**, while keeping the secret itself out of the report.

## Try it in your browser

1. Download or clone this project and open a terminal in the project folder. You need **Node.js 22 or newer**.
2. Run `npm run build:offline`.
3. Open `dist/secret-sweep.html` in your browser.
4. Click **Try sample scan**. You should see three findings from demo files: a GitHub token, a private key, and a sensitive `.env` value.
5. Click **Choose folder** to scan your own project.

Your files stay in your browser. Use the **Severity** filter to focus on High findings or click **Export JSON** to save the report.

**What if I get 0 findings?** The scanner found no matches in the files it checked. It skips binary files, some folders such as `node_modules`, and files larger than 2 MB.

## Use it with Git

Install Git and open a terminal in the project you want to scan. Replace the example path below with the location of `cli/git-sweep.cjs` on your computer.

| Command | What it does |
| --- | --- |
| `staged` | Checks the new or changed lines you marked for your next commit with `git add`. |
| `install-hook` | Runs that check before each commit. High findings stop the commit, and Medium findings are reported. If a pre-commit hook already exists, the installer leaves it in place. |
| `history` | Checks the commits available on your computer. It can find a secret in an older version of a file, even if you later deleted the file. |

```powershell
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" staged
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" install-hook
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" history --json
```

## Ignore a known test value

Sometimes a fake token in a test file looks like a real one. To ignore a specific rule for that file, create `.secretsweep.json` in the top folder of the project you want to scan.

```json
{
  "allow": [
    { "path": "tests/fixtures/demo.js", "rule": "GitHub token" }
  ]
}
```

Use the exact file path and copy the rule name from the scan results. This example ignores GitHub token matches in `tests/fixtures/demo.js`. The website reads the file when you choose the project folder. To use it in the pre-commit check, stage it with `git add .secretsweep.json`.



To run the automated tests, open a terminal in the project folder and run `npm test`.

