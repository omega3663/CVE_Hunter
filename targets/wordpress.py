import requests

class WordPressScraper:
    API_URL = "https://api.wordpress.org/plugins/info/1.2/"

    def fetch_batch(self, per_page=50, page=1, browse="popular"):
        """
        Returns a list of plugin metadata dicts:
          { slug, name, download_link, last_updated, description, size_kb, downloads }
        """
        params = {
            "action": "query_plugins",
            "request[per_page]": per_page,
            "request[page]": page,
            "request[browse]": browse
        }
        resp = requests.get(self.API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        plugins = []
        for p in data.get("plugins", []):
            plugins.append({
                "slug": p.get("slug"),
                "name": p.get("name"),
                "download_link": p.get("download_link"),
                "last_updated": p.get("last_updated"),
                "description": p.get("short_description") or p.get("description") or "",
                "size_kb": p.get("size") or 0,
                "downloads": p.get("downloaded") or 0,
            })
        return plugins, data.get("info", {}).get("pages", 1)
