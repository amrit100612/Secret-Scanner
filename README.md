# Secret Sweep

Secret Sweep finds API keys, passwords, and tokens that may have been left in your code. Your files stay in your browser when you use the website.

## Try it on your computer

1. Download or clone this project. Open a terminal in the project folder. You need Node.js 22 or newer.
2. Run `npm run build:offline`.
3. Open `dist/secret-sweep.html` in your browser.
4. Click **Try sample scan**. You should see three findings from demo files.
5. Click **Choose folder** to scan your own code.

Each finding shows the file, line number, and what the scanner found. The secret itself stays hidden, even in the JSON report. **0 findings** means the scanner found no matches in the files it checked. It skips binary files, some folders like `node_modules`, and files over 2 MB.

## Check your Git commits

Install Git, then open a terminal in the repo you want to check. Replace the example path below with the path to `cli/git-sweep.cjs` on your computer.

```powershell
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" staged
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" install-hook
node "C:/Tools/secret-sweep/cli/git-sweep.cjs" history
```

- **staged** checks the lines you have marked for your next commit with `git add`.
- **install-hook** makes Git run that check before every commit. A high-severity finding stops the commit. The installer leaves any existing hook in place.
- **history** checks old commits available on your computer, including files you deleted later. Add `--json` to get a JSON report.

The Git commands return `0` when there are no high-severity findings, `1` when they find one or more, and `2` if the scan could not finish.

## Ignore a known test value

If the scanner flags a fake token in a test file, add a file called `.secretsweep.json` to the top folder of your repo.

```json
{
  "allow": [
    { "path": "tests/fixtures/demo.js", "rule": "GitHub token" }
  ]
}
```

Copy the rule name from the scan results. Use the exact file path from the top of the repo, with `/` between folders. This example ignores every GitHub token match in that one file. The website reads the config when you choose the repo folder, and the history scan uses the current config. Run `git add .secretsweep.json` to use it in the pre-commit check.

## Put the website on Vercel

1. In Vercel, import this GitHub repo and keep the root directory as the repo's top folder.
2. Click **Deploy**. The included `vercel.json` tells Vercel to serve the website from `public/`. You can leave environment variables empty.
3. Open the deployed website and click **Try sample scan** to check that it works.

Run `npm test` in the project folder to run the automated tests.
