import os
import re
import time
import asyncio
import logging
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

COOKIE_FILENAMES = ["cookies.txt", "cookies", "cookie.txt", "cookie", "network", "chrome", "firefox", "edge", "brave"]

def is_cookie_file(fname: str) -> bool:
    if not fname: return False
    fname_lower = fname.lower()
    return any(cookie in fname_lower for cookie in COOKIE_FILENAMES)

def parse_netscape_cookies(text: str, domain_filter: str):
    results = []
    domain_filter = domain_filter.strip().lower().lstrip('.')
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        parts = re.split(r'\t', line, maxsplit=6)
        if len(parts) < 7: continue
        domain, flag, path, secure, expiry, name, value = parts
        dc = domain.lower().lstrip('.')
        if domain_filter in dc or dc in domain_filter:
            results.append('\t'.join([domain, flag, path, secure, expiry, name, value]))
    return results

@app.on_message(filters.text & ~filters.command("start"))
async def text_handler(client: Client, message: Message):
    uid = message.from_user.id if message.from_user else 0
    # If user is waiting for domain, resolve it
    if uid in pending_domains:
        future = pending_domains.pop(uid)
        if not future.done():
            future.get_loop().call_soon_threadsafe(future.set_result, message.text.strip().lower())

@app.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    await message.reply(
        "**🚀 Cookie Bot READY**\n\n"
        "🔹 Send a ZIP file\n"
        "🔹 Bot will ask for domain\n"
        "🔹 Reply with `netflix.com`\n\n"
        "**⚡ Optimized download + memory scan**",
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
        now = time.time()
        pct = current / filesize * 100
        if pct - last_pct[0] < 10: return
        last_pct[0] = pct
        bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
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
    avg_speed = filesize / elapsed / 1024 if elapsed > 0 else 0

    # Ask for domain - PROPER WAY using Future
    await status.edit_text(
        f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s\n\n"
        f"📝 **Send the domain name now:**\n"
        f"Example: `netflix.com` or `instagram.com`",
        parse_mode=enums.ParseMode.MARKDOWN
    )

    # Wait for domain using asyncio Future (no polling!)
    loop = asyncio.get_event_loop()
    future = loop.create_future()
    pending_domains[uid] = future

    try:
        domain = await asyncio.wait_for(future, timeout=60)
        print(f"🌐 DOMAIN: {domain}")
    except asyncio.TimeoutError:
        pending_domains.pop(uid, None)
        await status.edit_text("⏰ **Timed out.** Send the ZIP again and reply with domain within 60s.")
        if os.path.exists(zip_path): os.remove(zip_path)
        return

    # MEMORY SCAN
    await status.edit_text(f"🔍 **Scanning for `{domain}` cookies...**")

    total_matches = 0
    results = []
    scanned = 0

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                if is_cookie_file(member.filename):
                    scanned += 1
                    print(f"📄 Scanning: {member.filename}")
                    try:
                        with zf.open(member) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            matches = parse_netscape_cookies(content, domain)
                            if matches:
                                total_matches += len(matches)
                                results.append(f"**{member.filename}:**\n" + "\n".join(matches[:10]))
                                print(f"✅ {len(matches)} cookies found!")
                    except Exception as e:
                        print(f"⚠️ Skip {member.filename}: {e}")

        if os.path.exists(zip_path):
            os.remove(zip_path)

        if total_matches > 0:
            output = f"🎉 **{total_matches} COOKIES** for `{domain}`\n"
            output += f"📊 **{scanned} files** scanned:\n\n"
            output += "\n\n".join(results[:3])
            if len(results) > 3:
                output += f"\n\n... **+{len(results)-3} more files**"
            await status.edit_text(output, parse_mode=enums.ParseMode.MARKDOWN)
        else:
            await status.edit_text(
                f"❌ **No cookies** for `{domain}`\n"
                f"📁 **{scanned} files** scanned"
            )

    except Exception as e:
        print(f"❌ PROCESS ERROR: {e}")
        await status.edit_text(f"❌ **Error**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)

# Fake web server for Render free tier (port binding)
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
