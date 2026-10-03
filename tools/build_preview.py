"""Use the same interface in the installed app, standalone demo and inline preview."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "ip_scanner" / "app" / "web"
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)
document = (WEB / "index.html").read_text(encoding="utf-8")
body = document.split("<body>", 1)[1].split("</body>", 1)[0].strip()
css = (WEB / "styles.css").read_text(encoding="utf-8")
demo = (WEB / "demo.js").read_text(encoding="utf-8")
ui = (WEB / "app.js").read_text(encoding="utf-8")
fragment = (ROOT / "preview" / "fragment.html").read_text(encoding="utf-8")
fragment = fragment.replace("<!-- PREVIEW_STYLE -->", "<style>" + css + "</style>")
fragment = fragment.replace("<!-- PREVIEW_APP -->", body)
fragment = fragment.replace("<!-- PREVIEW_DEMO_SCRIPT -->", "<script>" + demo + "</script>")
fragment = fragment.replace("<!-- PREVIEW_UI_SCRIPT -->", "<script>" + ui + "</script>")
(OUT / "ip-scanner-preview.html").write_text(fragment, encoding="utf-8")
standalone = re.sub(r'\s*<base href="__BASE_PATH__">', '', document)
standalone = standalone.replace('<link rel="stylesheet" href="styles.css">', "<style>" + css + "</style>")
standalone = standalone.replace('<script src="api.js" defer></script>', "<script>" + demo + "</script>")
standalone = standalone.replace('<script src="app.js" defer></script>', '')
standalone = standalone.replace('</body>', '<script>' + ui + '</script></body>')
(OUT / "ip-scanner-demo.html").write_text(standalone, encoding="utf-8")
print("Preview and standalone demo written to", OUT)
