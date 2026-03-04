import os
import re
import time
import asyncio
import zipfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pyrogram import Client, filters, enums
from pyrogram.types import Message

BOT_TOKEN = "8663784484:AAEDaOYGkT8cCnkBvVaCNEp4fjQL3pgDPlQ"
API_ID = 32201838
API_HASH = "5e270d2e3ed53eb5d37c8f8016ff4bcd"

app = Client("cookiebot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Store pending domain requests: {user_id: asyncio.Future}
pending_domains = {}

# ── Cookie filename matching (from your CLI tool) ─────────────────────────────
COOKIE_FILENAMES_EXACT = {
    "cookies.txt", "cookies", "cookie.txt", "cookie",
    "network cookies", "network_cookies", "network cookies.txt",
    "chrome_cookies.txt", "firefox_cookies.txt", "chromium_cookies.txt",
    "edge_cookies.txt", "opera_cookies.txt", "default_cookies.txt",
    "brave_cookies.txt", "vivaldi_cookies.txt", "yandex_cookies.txt",
    "all cookies.txt", "all_cookies.txt", "allcookies.txt",
    "cookies (netscape).txt", "cookies_netscape.txt",
    "default cookies.txt", "default_cookies",
    "exported_cookies.txt", "browser_cookies.txt",
}
COOKIE_KEYWORDS = ["cookie"]

def is_cookie_file(fname: str) -> bool:
    fname_lower = os.path.basename(fname).lower().strip()
    if fname_lower in COOKIE_FILENAMES_EXACT:
        return True
    if fname_lower.replace(" ", "_") in COOKIE_FILENAMES_EXACT:
        return True
    for kw in COOKIE_KEYWORDS:
        if kw in fname_lower:
            return True
    return False

# ── Netscape cookie parser ────────────────────────────────────────────────────
def parse_netscape_cookies(text: str, domain_filter: str):
    domain_filter = domain_filter.strip().lower().lstrip(".")
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            parts = re.split(r"\s+", line, maxsplit=6)
        if len(parts) < 7:
            continue
        domain, flag, path, secure, expiry, name, value = parts[:7]
        domain_clean = domain.lower().lstrip(".")
        if domain_filter in domain_clean or domain_clean in domain_filter:
            results.append("\t".join([domain, flag, path, secure, expiry, name, value]))
    return results

# ── Recursive ZIP extraction into memory ─────────────────────────────────────
def collect_cookie_files_from_zip(zip_path: str, depth: int = 0, max_depth: int = 6):
    """
    Recursively opens ZIPs (including nested ZIPs) and returns list of
    (filename, content_bytes) for all cookie files found.
    """
    results = []
    if depth > max_depth:
        return results
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                fname = member.filename
                basename = os.path.basename(fname)

                if basename.lower().endswith('.zip'):
                    # Nested ZIP — extract to temp and recurse
                    try:
                        data = zf.read(member)
                        nested_path = f"/tmp/nested_{depth}_{int(time.time())}_{basename}"
                        with open(nested_path, 'wb') as f:
                            f.write(data)
                        nested = collect_cookie_files_from_zip(nested_path, depth + 1, max_depth)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested ZIP error {basename}: {e}")

                elif is_cookie_file(basename):
                    try:
                        content = zf.read(member)
                        results.append((fname, content))
                    except Exception as e:
                        print(f"⚠️ Read error {fname}: {e}")
    except zipfile.BadZipFile:
        print(f"⚠️ Bad ZIP: {zip_path}")
    except Exception as e:
        print(f"⚠️ ZIP open error: {e}")
    return results

# ── Telegram handlers ─────────────────────────────────────────────────────────
@app.on_message(filters.text & ~filters.command("start"))
async def text_handler(client: Client, message: Message):
    uid = message.from_user.id if message.from_user else 0
    if uid in pending_domains:
        future = pending_domains.pop(uid)
        if not future.done():
            future.get_loop().call_soon_threadsafe(future.set_result, message.text.strip().lower())

@app.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    await message.reply(
        "**🚀 Cookie Bot READY**\n\n"
        "🔹 Send a ZIP file\n"
        "🔹 Bot asks for domain\n"
        "🔹 Type `netflix.com`\n"
        "🔹 Receive ZIP → `NETFLIX_1.txt`, `NETFLIX_2.txt` ...\n\n"
        "✅ Supports nested ZIPs!",
        parse_mode=enums.ParseMode.MARKDOWN
    )

@app.on_message(filters.document)
async def doc_handler(client: Client, message: Message):
    doc_name = message.document.file_name if message.document else None
    if doc_name and 'zip' in doc_name.lower():
        await process_zip(client, message)
    else:
        await message.reply("❌ **ZIP file only** please!", parse_mode=enums.ParseMode.MARKDOWN)

async def process_zip(client: Client, message: Message):
    doc = message.document
    fname = doc.file_name or "upload.zip"
    filesize = doc.file_size or 0
    uid = message.from_user.id

    print(f"📥 ZIP: {fname} ({filesize/1e6:.1f}MB)")

    if filesize > 2e9:
        await message.reply("❌ Max 2GB")
        return

    start_time = time.time()
    zip_path = f"/tmp/{uid}_{int(time.time())}.zip"
    status = await message.reply("⬇️ **Downloading...**")

    last_pct = [0]
    async def progress(current, total):
        pct = current / filesize * 100
        if pct - last_pct[0] < 10: return
        last_pct[0] = pct
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        try:
            await status.edit_text(
                f"⬇️ **{fname}**\n[{bar}] **{pct:.1f}%**\n"
                f"{current/1e6:.1f}/{filesize/1e6:.1f} MB",
                parse_mode=enums.ParseMode.MARKDOWN
            )
        except: pass

    try:
        await client.download_media(message, file_name=zip_path, progress=progress)
        print("✅ DOWNLOAD COMPLETE")
    except Exception as e:
        await status.edit_text(f"❌ **Download failed**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)
        return

    elapsed = time.time() - start_time
    await status.edit_text(
        f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s\n\n"
        f"📝 **Send the domain name now:**\n"
        f"Example: `netflix.com` or `instagram.com`",
        parse_mode=enums.ParseMode.MARKDOWN
    )

    # Wait for domain
    loop = asyncio.get_event_loop()
    future = loop.create_future()
    pending_domains[uid] = future

    try:
        domain = await asyncio.wait_for(future, timeout=60)
        print(f"🌐 DOMAIN: {domain}")
    except asyncio.TimeoutError:
        pending_domains.pop(uid, None)
        await status.edit_text("⏰ **Timed out.** Send ZIP again.")
        if os.path.exists(zip_path): os.remove(zip_path)
        return

    await status.edit_text(f"🔍 **Scanning for `{domain}` cookies...**")

    # ── Scan using CLI tool logic ─────────────────────────────────────────────
    domain_prefix = domain.upper().split(".")[0]   # e.g. "NETFLIX"
    output_zip_path = f"/tmp/{uid}_{domain}_results.zip"
    total_matches = 0
    counter = 1
    scanned = 0

    try:
        cookie_files = collect_cookie_files_from_zip(zip_path)
        scanned = len(cookie_files)
        print(f"📁 Found {scanned} cookie files")

        # Delete input ZIP right after collecting
        if os.path.exists(zip_path):
            os.remove(zip_path)
            print("🧹 Input ZIP deleted")

        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf_out:
            for (orig_path, content_bytes) in cookie_files:
                try:
                    text = content_bytes.decode('utf-8', errors='ignore')
                    matches = parse_netscape_cookies(text, domain)
                    if matches:
                        out_name = f"{domain_prefix}_{counter}.txt"
                        zf_out.writestr(out_name, "\n".join(matches))
                        print(f"✅ {len(matches)} cookies → {out_name}")
                        total_matches += len(matches)
                        counter += 1
                except Exception as e:
                    print(f"⚠️ Parse error {orig_path}: {e}")

        if total_matches > 0:
            await status.edit_text(
                f"🎉 **{total_matches} cookies** found for `{domain}`\n"
                f"📁 {scanned} files scanned\n"
                f"📦 Sending ZIP...",
                parse_mode=enums.ParseMode.MARKDOWN
            )
            await client.send_document(
                message.chat.id,
                document=output_zip_path,
                caption=(
                    f"🍪 **{total_matches} cookies** for `{domain}`\n"
                    f"📄 Files: `{domain_prefix}_1.txt` → `{domain_prefix}_{counter-1}.txt`"
                ),
                parse_mode=enums.ParseMode.MARKDOWN
            )
            await status.delete()
        else:
            await status.edit_text(
                f"❌ **No cookies** found for `{domain}`\n"
                f"📁 {scanned} files scanned"
            )

    except Exception as e:
        print(f"❌ ERROR: {e}")
        await status.edit_text(f"❌ **Error**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)

    finally:
        if os.path.exists(output_zip_path):
            os.remove(output_zip_path)
            print("🧹 Output ZIP deleted")

# ── Fake web server for Render free tier ─────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

def run_server():
    HTTPServer(("0.0.0.0", 10000), Handler).serve_forever()

if __name__ == "__main__":
    print("🚀 Cookie Bot Starting...")
    threading.Thread(target=run_server, daemon=True).start()
    print("✅ Web server on port 10000")
    app.run()
