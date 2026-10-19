# Network Intrusion Detection System (Snort-based)

Snort-rule detection engine + Flask API + web dashboard. Replays labelled benign/attack traffic through
Snort-syntax rules and reports detection accuracy. Optionally ingests alerts from a real Snort install.

**Measured result (seed 7): 92% detection rate** (92/100 simulated attacks), 0 false positives on 300 benign events.
The 8 missed attacks are deliberately evasive (URL-encoded SQLi, slow scans, low-and-slow SSH, sub-threshold ICMP).
All traffic is synthetic; nothing is sent on a network.

## Structure
```
backend/   app.py (Flask API)  engine.py (rule parser/matcher)  simulator.py  snort_tail.py  rules/local.rules
frontend/  index.html (dashboard, served by Flask)
snort/     README.md (real Snort setup)     tests/  test_engine.py
```

## Run in VS Code
1. Unzip, then `File > Open Folder`. Needs Python 3.9+.
2. Terminal: Windows `run.bat` | Mac/Linux `./run.sh` (creates .venv, installs Flask, starts server).
3. Open http://127.0.0.1:5000 and click **Run attack simulation**.
Manual: `python -m venv .venv`, activate, `pip install -r requirements.txt`, `python backend/app.py`.
Tests: `pip install pytest && pytest`.

## Push to GitHub
1. Create an empty repo on github.com (no README), copy its URL.
2. In the project folder:
```
git init
git add .
git commit -m "Initial commit: Snort-based NIDS"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```
(Password prompt: use a Personal Access Token or sign in via the browser/Git Credential Manager.)

## Render deployment (OPTIONAL - not needed for a resume project)
Render hosts only the simulation dashboard; real Snort sniffing cannot run on Render.
1. Push the project to GitHub (above).
2. render.com > New > Web Service > connect the GitHub repo.
3. Runtime Python, Build `pip install -r requirements.txt`, Start `gunicorn --chdir backend app:app`
   (or use New > Blueprint, which reads render.yaml). Free plan, then Deploy.
4. Open the `https://<name>.onrender.com` URL. Free services sleep after inactivity (first load is slow).
Skipping Render is fine: put the GitHub link and a screenshot on your resume.
