# Push SCINT to GitHub

GitHub account: **iumangkaushik**
Run everything below in **PowerShell** on your own computer.

---

## One-time prep (skip if already done)

1. Install Git: https://git-scm.com  (accept all defaults during install)
2. You already have a GitHub account: `iumangkaushik`

Set your Git identity (only needed once, ever):

```powershell
git config --global user.name "Umang Kaushik"
git config --global user.email "umangkaushik0786@gmail.com"
```

---

## Step 1 — Make the first snapshot

```powershell
cd "C:\Users\umang\Downloads\SCINT_v6\project1_scint"
git init
git add .
git commit -m "Initial commit - SCINT v1.0 (GPCSSI 2026)"
```

> If you see a leftover/broken `.git` issue, run `Remove-Item -Recurse -Force .git` first, then redo Step 1.

---

## Step 2 — Create the empty repo on GitHub

1. Go to https://github.com/new
2. **Repository name:** `SCINT`
3. Leave **"Add a README file" UNCHECKED** (you already have one)
4. Keep it Public (so it shows in your portfolio) or Private — your choice
5. Click **Create repository**

---

## Step 3 — Connect and upload

```powershell
git branch -M main
git remote add origin https://github.com/iumangkaushik/SCINT.git
git push -u origin main
```

On `git push`, a browser window opens to sign in to GitHub — approve it.
When it finishes, refresh your repo page: your README becomes the project's front page.

Your repo will live at: **https://github.com/iumangkaushik/SCINT**

---

## From now on — no more v7, v8 folders

Every time you change something:

```powershell
git add .
git commit -m "describe what changed"
git push
```

Git keeps every version inside this one folder. You never copy the project again.

---

## Safety note

Your `.gitignore` already blocks `.env`, so your VirusTotal / AbuseIPDB API keys
will NOT be uploaded. Don't rename `.env` and you're safe.
