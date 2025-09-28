import streamlit as st
import os
import subprocess
import time
from scraper import main as run_scraper
from analyze import main as run_analyzer

st.set_page_config(page_title="CVE Hunter Dashboard", layout="wide")
st.title("🔍 CVE Hunter Pipeline UI")

# API Keys
git_api_key = st.text_input("GitHub API Key", value=os.getenv("GIT_API") or "", type="password")
gemini_api_key = st.text_input("Gemini API Key", value=os.getenv("GEMINI_API") or "", type="password")
if git_api_key: os.environ["GIT_API"] = git_api_key
if gemini_api_key: os.environ["GEMINI_API"] = gemini_api_key

# General Scraper Parameters
st.sidebar.header("Scraper Settings")
fresh_db = st.sidebar.checkbox("Start with a fresh database")
repo_limit = st.sidebar.slider("Max Projects to Scrape", 10, 200, 50)

# --- Github Sidebar Parameters ---
st.sidebar.subheader("Github Scraper Settings")
language = st.sidebar.selectbox("Language", ["PHP", "JavaScript", "Python", "TypeScript", "Go", "Java"])
stars = st.sidebar.slider("Stars (min..max)", 0, 10000, (20, 6000))
pushed_after = st.sidebar.selectbox("Last Pushed After", ["2024-01-01", "2023-01-01", "2022-01-01", "2020-01-01","2019-01-01","2018-01-01"])
min_size_kb = st.sidebar.number_input("Min Size (KB)", value=200)

keyword_prompt = st.sidebar.text_area(
    "Describe the type of app to find keywords for:",
    value="A simple CMS or admin dashboard with user authentication and forms.",
    height=150
)

# Wordpress scraper parameters
st.sidebar.subheader("Wordpress Scraper Settings")
wp_scrape = st.sidebar.checkbox("Scrape WordPress Plugins", value=False)


st.sidebar.header("Analyzer Settings")
semgrep_config = st.sidebar.text_input("Semgrep Rule Pack", value="p/security-audit")
model_choice = st.sidebar.selectbox("LLM Model", ["gemini-2.5-flash", "gemini-1.5-flash", "gemini-1.5-pro"])
max_analyze = st.sidebar.slider("Max Repos to Analyze", 10, 100, 50)

st.sidebar.subheader("Wordpress Analyzer Settings")
wp_analyze = st.sidebar.checkbox("Analyze WordPress Plugins", value=False)

# Helper: Stream subprocess logs live
def stream_logs(command, placeholder):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,encoding='utf-8',errors='replace')
    logs = ""
    for line in process.stdout:
        logs += line
        placeholder.text_area("Live Logs", logs, height=400)
    process.wait()
    if process.returncode == 0:
        st.success("✅ Completed successfully!")
    else:
        st.error(f"❌ Process exited with code {process.returncode}")

# --- Buttons ---
col1, col2 = st.columns(2)
with col1:
    if st.button("🚀 Run Scraper"):
        log_box = st.empty()
        st.info("Running GitHub scraper...")
        
        # --- Update the command with the new arguments ---
        if wp_scrape:
            # Run WordPress scraper mode
            cmd = [
                "python", "scraper.py",
                "--wordpress",
                "--limit", str(repo_limit),
            ]

        else:
            cmd = [
                "python", "scraper.py",
                "--limit", str(repo_limit),
                "--language", language,
                "--stars", f"{stars[0]}..{stars[1]}", # Format stars as a range
                "--pushed-after", pushed_after,
                "--min-size", str(min_size_kb),
                "--keyword-prompt", keyword_prompt
            ]

        # Conditionally add the --fresh-db flag
        if fresh_db:
            cmd.append("--fresh-db")

        stream_logs(cmd, log_box)

with col2:
    if st.button("🛠 Run Analyzer"):
        log_box = st.empty()
        st.info("Running analyzer...")

        if wp_scrape:
            # Run WordPress scraper mode
            cmd = [
                "python", "analyze.py",
                "--wordpress",
                "--max", str(max_analyze),
                "--semgrep-config", semgrep_config,
                "--model", model_choice
            ]

        else:
            cmd = [
                "python", "analyze.py",
                "--max", str(max_analyze),
                "--semgrep-config", semgrep_config,
                "--model", model_choice
            ]        

        stream_logs(cmd, log_box)

# Reports Section
st.header("📜 Reports")
reports_dir = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(reports_dir, exist_ok=True)
reports = sorted([f for f in os.listdir(reports_dir) if f.endswith(".md")], reverse=True)

if reports:
    selected_report = st.selectbox("Select a report", reports)
    with open(os.path.join(reports_dir, selected_report), "r", encoding="utf-8") as f:
        st.markdown(f.read())
    st.download_button("Download Report", data=open(os.path.join(reports_dir, selected_report), "rb"), file_name=selected_report)
else:
    st.info("No reports yet. Run the analyzer to generate one.")
