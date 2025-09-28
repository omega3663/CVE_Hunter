import argparse
import os
import subprocess
import sqlite3
import time
import shutil
import stat
import json
import re
import glob
import google.generativeai as genai
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import zipfile
import io
import requests
sys.stdout.reconfigure(encoding='utf-8')

import datetime

# === Parse CLI Arguments ===
parser = argparse.ArgumentParser(description="Analyze repos with Semgrep and Gemini")
parser.add_argument("--max", type=int, default=50, help="Max repos to analyze")
parser.add_argument("--semgrep-config", type=str, default="p/security-audit", help="Semgrep ruleset")
parser.add_argument("--model", type=str, default="gemini-2.5-flash", help="Gemini model to use")
parser.add_argument("--wordpress", action="store_true", help="Analyze wordpress plugins")
args = parser.parse_args()

MAX_REPOS = args.max
SEMGREP_CONFIG = args.semgrep_config
load_dotenv(override=True)


# Replace model setup:
model = ChatGoogleGenerativeAI(
    model=args.model,
    google_api_key=os.getenv("GEMINI_API"),
    temperature=0.2,
)

### conditional prompt selection
if args.wordpress:

# wordpress prompt
    prompt_template = ChatPromptTemplate.from_template("""
    You are a security analyst reviewing Semgrep findings from an open-source WordPress plugin.

    Below is the Semgrep scan output in JSON format, including file paths, filenames, and vulnerable code snippets.

    {semgrep_results}

    Your tasks:
    1. Focus on identifying potential **SQL Injection** and **Local File Inclusion (LFI)** vulnerabilities.
    2. Look at file paths and filenames to assess if they are web-exposed or related to user input, especially typical WordPress plugin files such as PHP files handling requests, form inputs, AJAX handlers, or template includes.
    3. Identify findings where the vulnerable code involves **user-controlled input** (e.g., $_GET, $_POST, $_REQUEST, or other HTTP inputs).
    4. **Ignore vulnerabilities that require administrator-level privileges to exploit**.
    5. If no SQLi or LFI vulnerabilities meeting these criteria are found (or the only ones found require admin-privileges), respond ONLY with: "NO PROMISING VULNERABILITY FOUND".

    Output a short, concise analysis highlighting:
    - Relevant file paths and why they appear web-exposed.
    - Vulnerable code snippets and why they indicate user input.
    - A brief rationale for why this plugin warrants deeper investigation.

    Be concise and structured in your response.
    """)

### otherwise, github prompt
else:
    prompt_template = ChatPromptTemplate.from_template("""
    You are a security analyst reviewing Semgrep findings from an open-source web app or plugin.

    Below is the Semgrep scan output in JSON format, including file paths, filenames, and vulnerable code snippets.
                                                    
    {semgrep_results}

    Your tasks:
    1. Look at the **file paths and filenames** to assess if they are web-exposed or related to user input 
    (e.g., login.php, routes/user.js, views/, templates/, controllers/, api/, etc.).
    2. Identify any findings where the vulnerable code likely involves **user-controlled input** 
    (e.g., $_GET, $_POST, request.params, request.form, req.query, etc.).
    3. Prioritize vulnerabilities that are realistic in a **deployed CMS/CRM/dashboard** context.
    4. If no evidence is found of web exposure, do not assume that the repo could be web exposed.
    5. If no vulnerabilities meet these criteria, respond ONLY with: "NO PROMISING VULNERABILITY FOUND".

    Output a short analysis highlighting:
    - Relevant file paths and why they appear web-exposed.
    - Vulnerable code snippets and why they indicate user input.
    - A brief rationale for why this repo is worth deeper investigation.

    Be concise and structured in your response.
    """)

chain = prompt_template | model | StrOutputParser()

CLONE_DIR = os.path.join(os.path.dirname(__file__), "repos")
LLM_DELAY_SEC = 6

LFI_SQLI_RULES = {
    # SQLi
    "php.lang.security.injection.tainted-sql-string.tainted-sql-string",    
    # LFI / Path Traversal
    "php.lang.security.tainted-path-traversal",
}

# filter wordpress LFI to rules I care about
def filter_lfi_sqli_findings(semgrep_json):
    try:
        data = json.loads(semgrep_json)
        results = data.get("results", [])
    except json.JSONDecodeError:
        return []

    filtered = []
    for finding in results:
        rule_id = finding.get("check_id", "")
        if rule_id in LFI_SQLI_RULES:
            filtered.append(finding)

    return filtered

# pull wordpress plugin
def download_and_extract_wordpress_plugin(full_name, download_url):
    plugin_dir = os.path.join(CLONE_DIR, full_name.replace("/", "_"))
    if os.path.exists(plugin_dir):
        print(f"Plugin {full_name} already downloaded.")
        return plugin_dir
    print(f"Downloading and extracting WordPress plugin {full_name}...")
    try:
        r = requests.get(download_url, timeout=60)
        r.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(r.content))
        os.makedirs(plugin_dir, exist_ok=True)
        z.extractall(plugin_dir)
        return plugin_dir
    except Exception as e:
        print(f"❌ Failed to download/extract plugin {full_name}: {e}")
        return None
    
# fetch wordpress plugin from db
def fetch_all_wordpress_plugins(run_id, db_path, limit=MAX_REPOS):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, full_name, clone_url FROM repos
        WHERE run_id = ? AND full_name LIKE 'wordpress/%'
        ORDER BY id DESC
        LIMIT ?
    """, (run_id, limit))
    plugins = cursor.fetchall()
    conn.close()
    return plugins

def find_latest_db(pattern="repos*.db"):
    """Finds the database file with the highest number."""
    db_files = glob.glob(pattern)
    if not db_files:
        raise FileNotFoundError("❌ No database files found. Run scraper.py first.")
    
    # Sort files naturally (so repos10.db comes after repos9.db)
    db_files.sort(key=lambda f: int(re.search(r'(\d+)', f).group(0)) if re.search(r'(\d+)', f) else 0)
    
    latest_db = db_files[-1]
    print(f"ℹ️ Found latest database: {latest_db}")
    return latest_db

# === DB Helpers ===
def get_latest_run_id(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(run_id) FROM repos")
    result = cursor.fetchone()
    if result and result[0]:
        return result[0]
    raise ValueError("❌ No runs found. Run scraper.py first.")

def fetch_all_repos(run_id, db_path, limit=MAX_REPOS):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, full_name, clone_url FROM repos
        WHERE run_id = ?
        ORDER BY stars DESC
        LIMIT ?
    """, (run_id, limit))
    repos = cursor.fetchall()
    conn.close()
    return repos

def add_semgrep_column_if_missing(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(repos)")
    cols = [row[1] for row in cursor.fetchall()]
    if "semgrep_json" not in cols:
        cursor.execute("ALTER TABLE repos ADD COLUMN semgrep_json TEXT")
    conn.commit()
    conn.close()

def store_semgrep_results(repo_id, semgrep_json,db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE repos SET semgrep_json = ? WHERE id = ?", (semgrep_json, repo_id))
    conn.commit()
    conn.close()

# === Repo Processing ===
def clone_repo(full_name, clone_url):
    repo_dir = os.path.join(CLONE_DIR, full_name.replace("/", "_"))
    if os.path.exists(repo_dir):
        print(f"Repo {full_name} already cloned.")
        return repo_dir
    print(f"Cloning {full_name}...")
    try:
        subprocess.run(["git", "clone", "--depth=1", clone_url, repo_dir], check=True)
        return repo_dir
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to clone {full_name}: {e}")
        return None

def run_semgrep(repo_dir):
    print(f"Running Semgrep on {repo_dir} with {SEMGREP_CONFIG}...")
    try:
        result = subprocess.run(
            ["semgrep", "--timeout", "15", "--json", "-q", "-c", SEMGREP_CONFIG, repo_dir],
            capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Semgrep scan failed: {e}")
        return None

def analyze_with_llm(semgrep_json, is_wordpress=False):
    if is_wordpress:
        # Only keep LFI/SQLi findings for WordPress
        filtered_findings = filter_lfi_sqli_findings(semgrep_json)
        if not filtered_findings:
            return "NO PROMISING VULNERABILITY FOUND"
        input_json = json.dumps({"results": filtered_findings})
    else:
        # Keep all findings for GitHub/web app repos
        input_json = semgrep_json

    # Call the LLM
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = chain.invoke({"semgrep_results": input_json})
            time.sleep(LLM_DELAY_SEC)
            return response
        except Exception as e:
            print(f"LLM error (attempt {attempt+1}): {e}")
            time.sleep(LLM_DELAY_SEC * (attempt + 1))
    return "LLM ANALYSIS FAILED"


# === Cleanup & Report ===
def handle_remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def cleanup_clones():
    if os.path.exists(CLONE_DIR):
        print(f"🧹 Cleaning {CLONE_DIR}...")
        shutil.rmtree(CLONE_DIR, onerror=handle_remove_readonly)

def write_report(reports):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"report-{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Vulnerability Analysis Report\nGenerated: {ts}\n\n")
        for full_name, summary in reports:
            f.write(f"## {full_name}\n\n{summary}\n\n---\n\n")
    print(f"✅ Report written: {path}")

# === Main Driver ===
def main():
    DB_PATH = find_latest_db()
    add_semgrep_column_if_missing(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    run_id = get_latest_run_id(conn)
    conn.close()

    if not os.path.exists(CLONE_DIR):
        os.makedirs(CLONE_DIR)

    report_data = []
    repo_dirs = []
    repo_map = {}

    # if wordpress plugins
    if args.wordpress:
        # fetch wordpress plugins
        wp_plugins = fetch_all_wordpress_plugins(run_id, DB_PATH, limit=MAX_REPOS)

        # Download & extract WordPress plugins
        for repo_id, full_name, download_url in wp_plugins:
            plugin_dir = download_and_extract_wordpress_plugin(full_name, download_url)
            if plugin_dir:
                repo_dirs.append(plugin_dir)
                repo_map[plugin_dir] = (repo_id, full_name)


    # otherwise, github
    else:
        #fetch github repos
        repos = fetch_all_repos(run_id, DB_PATH, limit=MAX_REPOS)

        # Clone github repos sequentially (avoid git conflicts)    
        for repo_id, full_name, clone_url in repos:
            repo_dir = clone_repo(full_name, clone_url)
            if repo_dir:
                repo_dirs.append(repo_dir)
                repo_map[repo_dir] = (repo_id, full_name)
    

    # Run Semgrep scans in parallel
    print(f"⚡ Running Semgrep scans in parallel ({min(6, len(repo_dirs))} workers)...")
    semgrep_results = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_repo = {executor.submit(run_semgrep, rd): rd for rd in repo_dirs}
        for future in as_completed(future_to_repo):
            repo_dir = future_to_repo[future]
            repo_id, full_name = repo_map[repo_dir]
            try:
                semgrep_json = future.result()
                semgrep_results[repo_dir] = semgrep_json
                store_semgrep_results(repo_id, semgrep_json,DB_PATH)
            except Exception as e:
                print(f"❌ Semgrep failed for {full_name}: {e}")

    # Analyze results with AI (sequential, since it's rate-limited)
    for repo_dir, semgrep_json in semgrep_results.items():
        repo_id, full_name = repo_map[repo_dir]
        print(f"🔎 Analyzing {full_name} with LLM...")
        analysis = analyze_with_llm(semgrep_json,is_wordpress=args.wordpress)
        if "NO PROMISING VULNERABILITY FOUND" not in analysis:
            report_data.append((full_name, analysis))
            print(f"✅ {full_name} flagged as promising.")
        else:
            print(f"🚫 {full_name} skipped (no exploitable vuln).")

    if report_data:
        write_report(report_data)
    else:
        print("🚫 No promising vulnerabilities this run.")

    cleanup_clones()

if __name__ == "__main__":
    main()
