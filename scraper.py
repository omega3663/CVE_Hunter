
import argparse
import requests, zipfile, io, os
from github import Github
import csv
import google.generativeai as genai
import os
import time
from github.GithubException import GithubException
import sqlite3
from dotenv import load_dotenv
import random
import sys
import glob
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from targets.wordpress import WordPressScraper
import json


CLONE_DIR = os.path.join(os.path.dirname(__file__), "repos")
DB_PATH = "repos2.db"
os.makedirs(CLONE_DIR, exist_ok=True)
sys.stdout.reconfigure(encoding='utf-8')

# === Parse CLI Arguments ===
parser = argparse.ArgumentParser(description="Open Source scraper for vulnerable repos")

# general args
parser.add_argument("--fresh-db", action="store_true", help="Delete the existing database and start fresh")
parser.add_argument("--limit", type=int, default=50, help="Max items to pull")

# wordpress plugin scraping args
parser.add_argument("--wordpress", action="store_true", help="Fetch WordPress.org plugins (download zips)")
parser.add_argument("--browse", default="updated",type=str, help="WordPress browse mode (new, updated, popular)")

# github project scraping args
parser.add_argument("--language", type=str, default="PHP", help="Language to search for")
parser.add_argument("--stars", type=str, default="20..6000", help="Star range (e.g., '20..6000')")
parser.add_argument("--pushed-after", type=str, default="2023-01-01", help="Last pushed after date (e.g., '2023-01-01')")
parser.add_argument("--min-size", type=int, default=200, help="Minimum size in KB")
parser.add_argument("--keyword-prompt", type=str, default="A simple CMS or admin dashboard with user authentication and forms.", help="Natural language prompt for generating keywords")

args = parser.parse_args()

repo_limit = args.limit

# === Load API Keys ===
load_dotenv(override=True)
git_key = os.getenv("GIT_API")
git_api = Github(git_key)


# Initialize the generative AI model
llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=os.getenv("GEMINI_API"))
prompt_template = ChatPromptTemplate.from_template("""
You are an expert at brainstorming GitHub search keywords.
Based on the user's description of an application, generate a list of 5 relevant keywords.

**Instructions:**
- The keywords should be joined by ' OR '.
- The entire list should be enclosed in parentheses.
- Do not include any other text, explanation, or markdown.

**User App Description:** "{user_prompt}"

**Example Output:** `(login OR signup OR register OR admin OR cms OR dashboard OR user OR account OR auth)`
""")
keyword_generation_chain = prompt_template | llm | StrOutputParser()

# state tracking for wordpress scrape so it picks up where it left off
STATE_FILE = "wordpress_state.json"


# extract wordpress plugin zip files
def download_and_extract_zip(url, dest_dir):
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        z = zipfile.ZipFile(io.BytesIO(r.content))
        os.makedirs(dest_dir, exist_ok=True)
        # Extract into dest_dir. WordPress zips usually have a top-level folder; extracting as-is is fine.
        z.extractall(dest_dir)
        return True
    except Exception as e:
        print(f"❌ Failed to download/extract {url}: {e}")
        return False

# import and use wordpress scraper
def scrape_wordpress(conn, limit=50):
    # Load previous state
    state_file = "wordpress_state.json"
    if os.path.exists(state_file):
        with open(state_file) as f:
            state = json.load(f)
    else:
        state = {"browse": args.browse, "page": 1, "total_pages": None}

    browse = args.browse
    page = state.get("page", 1)
    total_pages = state.get("total_pages")

    print(f"[+] Fetching WordPress plugins: browse={browse}, page={page}")
    scraper = WordPressScraper()
    run_id = get_next_run_id(conn)
    added = 0
    per_page = min(limit, 250)  # max per_page = 250

    while added < limit:
        print(f"[+] Fetching WordPress plugins: browse={browse}, page={page}")
        plugins, fetched_total_pages = scraper.fetch_batch(per_page=per_page, page=page, browse=browse)

        # On first request, update total_pages in state
        if total_pages is None:
            total_pages = fetched_total_pages
            print(f"[INFO] Total pages set to {total_pages}")

        if not plugins:
            print("[INFO] No plugins returned, stopping.")
            break

        for p in plugins:
            if added >= limit:
                break
            full_name = f"wordpress/{p['slug']}"
            if already_seen(conn, full_name):
                print(f"⚠️ Skipping already seen: {full_name}")
                continue

            plugin_dir = os.path.join(CLONE_DIR, p["slug"])
            print(f"✅ Found: {full_name}")
            if not download_and_extract_zip(p["download_link"], plugin_dir):
                continue

            repo_data = {
                "full_name": full_name,
                "url": f"https://wordpress.org/plugins/{p['slug']}/",
                "stars": 0,
                "forks": 0,
                "language": "PHP",
                "last_push": p["last_updated"],
                "description": p["description"],
                "clone_url": p["download_link"],
                "open_issues": 0,
                "size_kb": p["size_kb"],
            }
            insert_into_db(conn, repo_data, run_id)
            added += 1

        page += 1
        if total_pages and page > total_pages:
            page = 1  # wrap to start if desired, or break if you want to stop after one full pass
            print("[INFO] Reached last page, wrapping to page 1")

        if added >= limit:
            print(f"[INFO] Reached limit of {limit} plugins, stopping.")

    print(f"[+] Added {added} new WordPress plugins")

    # Save updated state
    state["page"] = page
    state["total_pages"] = total_pages
    with open(state_file, "w") as f:
        json.dump(state, f)



def generate_keywords_with_ai(prompt: str) -> str:
    """
    Generates a GitHub keyword search string using a generative AI model.
    """
    print(f"🤖 Generating keywords with AI from prompt: '{prompt}'")
    try:
        keywords = keyword_generation_chain.invoke({"user_prompt": prompt})
        print(f"✅ AI-generated keywords: {keywords}")
        return keywords
    except Exception as e:
        print(f"❌ Failed to generate keywords with AI: {e}")
        # Fallback to a default keyword set in case of failure
        return "(login OR admin OR cms)"


def find_latest_db(pattern="repos*.db"):
    """Finds the database file with the highest number, or returns a default."""
    db_files = glob.glob(pattern)
    if not db_files:
        return "repos2.db" # Use repos2.db if no databases exist yet

    # This sorts files like 'repos10.db' correctly after 'repos9.db'
    db_files.sort(key=lambda f: int(re.search(r'(\d+)', f).group(0)) if re.search(r'(\d+)', f) else 0)
    return db_files[-1]

def get_next_db_filename(base_name="repos"):
    """Finds the next available database filename, e.g., repos3.db, repos4.db."""
    index = 2
    while True:
        db_path = f"{base_name}{index}.db"
        if not os.path.exists(db_path):
            return db_path
        index += 1

def search_repos(query: str, max_results=repo_limit,per_page=50):
    sort_choice = random.choice(["updated", "forks"])
    order_choice = random.choice(["asc", "desc"])
    start_page = random.randint(1, 5)

    print(f"🔎 Query: {query}")
    print(f"📋 sort={sort_choice}, order={order_choice}, starting page={start_page}")

    results = []
    page = start_page

    while len(results) < max_results:
        try:
            repos_page = git_api.search_repositories(
                query=query,
                sort=sort_choice,
                order=order_choice,
                per_page=per_page
            ).get_page(page - 1)
            
            if not repos_page:
                break
            
            results.extend(repos_page)
            print(f"Fetched page {page}, total repos collected: {len(results)}")

            if len(results) >= max_results:
                break
            page += 1

        except GithubException as e:
            if e.status == 403:
                rate = git_api.get_rate_limit().search
                reset_time = rate.reset.timestamp()
                sleep_duration = reset_time - time.time() + 5
                if sleep_duration > 0:
                    print(f"Rate limit hit. Sleeping for {int(sleep_duration)} seconds...")
                    time.sleep(sleep_duration)
            else:
                print(f"GithubException: {e}")
                break

        except Exception as e:
            print(f"Unexpected error: {e}")
            break

    return results[:max_results]




# save repo metadata
def save_repo_metadata(repo):
    return {
        "full_name": repo.full_name,
        "url": repo.html_url,
        "stars": repo.stargazers_count,
        "forks": repo.forks_count,
        "language": repo.language,
        "last_push": str(repo.pushed_at),
        "description": repo.description,
        "clone_url": repo.clone_url,
        "open_issues": repo.open_issues_count,
        "size_kb": repo.size
    }

# check for already seen repos
def already_seen(conn, full_name):
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM repos WHERE full_name = ?", (full_name,))
    return cursor.fetchone() is not None

# setup db
def setup_db(db_path="repos2.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT UNIQUE,
            url TEXT,
            stars INTEGER,
            forks INTEGER,
            language TEXT,
            last_push TEXT,
            description TEXT,
            clone_url TEXT,
            open_issues INTEGER,
            size_kb INTEGER,
            tier1_rank INTEGER,
            tier2_rank INTEGER,
            final_rank INTEGER,
            run_id INTEGER
        )
    ''')
    conn.commit()
    return conn

# pull run id
def get_next_run_id(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(run_id) FROM repos")
    result = cursor.fetchone()
    return (result[0] or 0) + 1


# write repo data to sqlite db
def insert_into_db(conn, repo_data,run_id):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO repos (
            full_name, url, stars, forks, language,
            last_push, description, clone_url, open_issues, size_kb, run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        repo_data["full_name"],
        repo_data["url"],
        repo_data["stars"],
        repo_data["forks"],
        repo_data["language"],
        repo_data["last_push"],
        repo_data["description"],
        repo_data["clone_url"],
        repo_data["open_issues"],
        repo_data["size_kb"],
        run_id
    ))
    conn.commit()

def main():
    if args.fresh_db:
        db_path = get_next_db_filename()
        print(f"🚀 --fresh-db set. Creating new database: {db_path}")
    else:
        db_path = find_latest_db()
        print(f"✍️  Incrementing latest database: {db_path}")

    # FIX #1: Pass the correct db_path to the setup function
    conn = setup_db(db_path)
    current_run_id = get_next_run_id(conn)
    new_repos_count = 0

    # wordpress scrape
    if args.wordpress:
        scrape_wordpress(conn, limit=args.limit)

    # else, github scrape
    else:        

        language = args.language
        pushed_after = args.pushed_after
        keyword_prompt = args.keyword_prompt

        print(f"   - Language: {language}")
        print(f"   - Pushed After: {pushed_after}")
        print(f"   - App Type: {keyword_prompt}")

        keywords = generate_keywords_with_ai(keyword_prompt)

        query_parts = [
            f"language:{language}",
            f"stars:{args.stars}",
            f"pushed:>{pushed_after}",
            f"size:>{args.min_size}",
            "archived:false",
            f"{keywords} in:readme,description"
        ]
        github_query = " ".join(query_parts)

        repos = search_repos(query=github_query, max_results=args.limit)

        for repo in repos:
            meta = save_repo_metadata(repo)
            print(f"Checking: {meta['full_name']} (stars={meta['stars']}, forks={meta['forks']})")

            if already_seen(conn, meta["full_name"]):
                print(f"⚠️ Skipping already seen: {meta['full_name']}")
                continue

            print("✅ Found:", meta["full_name"])
            insert_into_db(conn, meta, current_run_id)
            new_repos_count += 1

        if new_repos_count == 0:
            print(f"🚫 No new repos found.")
            # We don't exit here anymore, just report
    
        print(f"✅ Scraper finished. {new_repos_count} new repos added for run_id {current_run_id}.")

    conn.close()

if __name__ == "__main__":
    main()