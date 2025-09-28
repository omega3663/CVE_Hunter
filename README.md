# 🔍 CVE Hunter

**CVE Hunter** is an AI-powered research framework for discovering vulnerabilities in open-source software.  

It scrapes candidate projects (from GitHub or WordPress plugins), stores metadata in SQLite, and then runs Semgrep and AI analysis to flag likely vulnerabilities.  

A Streamlit UI ties it all together with an interactive dashboard and report viewer.

---

## ✨ Features

- **Target Acquisition**
  - 🔧 GitHub scraping (filter by language, stars, size, push date, keywords via prompt → AI-generated search terms)
  - 🔌 WordPress plugin scraping (direct from the official API)
- **Analysis**
  - Static analysis with [Semgrep](https://semgrep.dev/) (configurable ruleset, defaults to `p/security-audit`)
  - AI-assisted scoring & triage with Gemini (multiple models supported)
- **Frontend**
  - Streamlit dashboard to run scrapes/analysis, view logs in real time, and explore generated markdown reports
- **Storage**
  - Lightweight SQLite DB for scraped metadata + analysis results
- **Reports**
  - Auto-generated markdown reports per run, viewable/downloadable in the dashboard

---

## ⚡ Installation

Clone the repo and set up a Python environment:

```
git clone https://github.com/omega3663/CVE_Hunter
cd CVE_Hunter
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
python -m pip install -r requirements.txt
```

You’ll also need:

- [Semgrep](https://semgrep.dev/) installed and in your `PATH`.
- API keys:
  - **GitHub API key** (recommended for higher request limits).
  - **Gemini API key** (for LLM-based analysis).

---

## ⚙️ Usage - Streamlit Dashboard

```
streamlit run streamlit_app.py
```

From the UI you can:

- Configure GitHub/WordPress scraper options.

- Run scraping and analysis jobs.

- View live logs while jobs run.

- Browse and download generated reports. 


## ⚙️ Usage - CLI Mode

#### Scrape GitHub Projects

```
python scraper.py \
  --limit 50 \
  --language PHP \
  --stars 20..6000 \
  --pushed-after 2023-01-01 \
  --min-size 200 \
  --keyword-prompt "A simple CMS or admin dashboard with user authentication and forms."
  
```
 
#### Scrape Wordpress Plugins
```
python scraper.py --wordpress --limit 50
```

#### Analyze GitHub Projects
```
python analyze.py \
  --max 50 \
  --semgrep-config p/security-audit \
  --model gemini-1.5-flash
```
 
#### Analyze WordPress Plugins
```
python analyze.py --wordpress --max 50 --semgrep-config p/security-audit --model gemini-1.5-flash
```

👉 Reports are saved under reports/.


## 📜 Reports

Each analysis run produces a Markdown file in the reports/ directory.

Reports include:

- Project metadata (name, stars, size, etc.).

- Semgrep findings.

- LLM summaries & prioritization.

You can view reports directly in Streamlit or with any Markdown viewer.


## 🧭 Roadmap

- Add multi-model support (Ollama, local LLMs).
- Add modules for other open-source ecosystems (PyPI, npm, laravel, etc.)
- Augment Semgrep and LLM analysis with REGEX enabled checks to filter out more false positives

