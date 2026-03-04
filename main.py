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

pending_domains = {}
pending_passwords = {}

# ── Cookie filename matching ──────────────────────────────────────────────────
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

# ── Check if ZIP is password protected ───────────────────────────────────────
def is_zip_encrypted(zip_path: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                if member.flag_bits & 0x1:  # encryption flag
                    return True
        return False
    except:
        return False

# ── Validate cookie line ──────────────────────────────────────────────────────
def is_valid_netscape_line(parts: list) -> bool:
    if len(parts) < 7:
        return False
    domain, flag, path, secure, expiry, name, value = parts[:7]
    if not domain or '.' not in domain:
        return False
    if flag.upper() not in ('TRUE', 'FALSE'):
        return False
    if not path.startswith('/'):
        return False
    if secure.upper() not in ('TRUE', 'FALSE'):
        return False
    if not expiry.isdigit():
        return False
    if not name or ' ' in name or not name.isprintable():
        return False
    return True

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
        if not is_valid_netscape_line(parts):
            continue
        domain, flag, path, secure, expiry, name, value = parts[:7]
        domain_clean = domain.lower().lstrip(".")
        if domain_filter in domain_clean or domain_clean in domain_filter:
            results.append("\t".join([domain, flag, path, secure, expiry, name, value]))
    return results

# ── Recursive ZIP collector (with optional password) ─────────────────────────
def collect_cookie_files_from_zip(zip_path: str, password: bytes = None, depth: int = 0, max_depth: int = 6):
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
                    try:
                        data = zf.read(member, pwd=password)
                        nested_path = f"/tmp/nested_{depth}_{int(time.time())}_{basename}"
                        with open(nested_path, 'wb') as f:
                            f.write(data)
                        nested = collect_cookie_files_from_zip(nested_path, password, depth + 1, max_depth)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested ZIP error {basename}: {e}")

                elif is_cookie_file(basename):
                    try:
                        content = zf.read(member, pwd=password)
                        results.append((fname, content))
                    except Exception as e:
                        print(f"⚠️ Read error {fname}: {e}")
    except zipfile.BadZipFile:
        print(f"⚠️ Bad ZIP: {zip_path}")
    except Exception as e:
        print(f"⚠️ ZIP open error: {e}")
    return results

# ── Text handler (domain + password) ─────────────────────────────────────────
@app.on_message(filters.text & ~filters.command("start"))
async def text_handler(client: Client, message: Message):
    uid = message.from_user.id if message.from_user else 0

    # Check password first
    if uid in pending_passwords:
        future = pending_passwords.pop(uid)
        if not future.done():
            future.get_loop().call_soon_threadsafe(future.set_result, message.text.strip())
        return

    # Then domain
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
        "🔹 Receive `NETFLIX_1.txt`, `NETFLIX_2.txt` ...\n\n"
        "🔐 Password-protected ZIPs supported\n"
        "✅ Only valid Netscape cookies saved\n"
        "✅ Nested ZIPs supported",
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

    if filesize > 2e9:
        await message.reply("❌ Max 2GB")
        return

    start_time = time.time()
    zip_path = f"/tmp/{uid}_{int(time.time())}.zip"
    status = await message.reply("⬇️ **Downloading...**")

    # ── Progress bar with speed + ETA ────────────────────────────────────────
    last_update_time = [time.time()]
    last_update_bytes = [0]

    async def progress(current, total):
        now = time.time()
        elapsed_since_last = now - last_update_time[0]
        if elapsed_since_last < 2.0:
            return
        bytes_since_last = current - last_update_bytes[0]
        speed_bps = bytes_since_last / elapsed_since_last if elapsed_since_last > 0 else 0
        remaining = total - current
        eta = int(remaining / speed_bps) if speed_bps > 0 else 0
        last_update_time[0] = now
        last_update_bytes[0] = current
        pct = current / total * 100
        filled = int(pct / 5)
        bar = "█" * filled + "░" * (20 - filled)
        if speed_bps >= 1_000_000:
            speed_str = f"{speed_bps/1_000_000:.1f} MB/s"
        elif speed_bps >= 1_000:
            speed_str = f"{speed_bps/1_000:.0f} KB/s"
        else:
            speed_str = f"{speed_bps:.0f} B/s"
        eta_str = f"{eta//60}m {eta%60}s" if eta >= 60 else f"{eta}s"
        try:
            await status.edit_text(
                f"⬇️ **Downloading** `{fname}`\n"
                f"`[{bar}]` **{pct:.1f}%**\n"
                f"📦 {current/1e6:.1f} / {total/1e6:.1f} MB\n"
                f"⚡ **{speed_str}** | ⏱️ ETA: **{eta_str}**",
                parse_mode=enums.ParseMode.MARKDOWN
            )
        except: pass

    try:
        await client.download_media(message, file_name=zip_path, progress=progress)
    except Exception as e:
        await status.edit_text(f"❌ **Download failed**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)
        return

    elapsed = time.time() - start_time
    avg_speed = filesize / elapsed if elapsed > 0 else 0
    avg_str = f"{avg_speed/1_000_000:.1f} MB/s" if avg_speed >= 1_000_000 else f"{avg_speed/1_000:.0f} KB/s"

    # ── Check if ZIP is password protected ───────────────────────────────────
    zip_password = None
    if is_zip_encrypted(zip_path):
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s @ {avg_str}\n\n"
            f"🔐 **ZIP is password protected!**\n"
            f"Please send the password now:",
            parse_mode=enums.ParseMode.MARKDOWN
        )

        loop = asyncio.get_event_loop()
        pwd_future = loop.create_future()
        pending_passwords[uid] = pwd_future

        try:
            pwd_text = await asyncio.wait_for(pwd_future, timeout=60)
            zip_password = pwd_text.encode('utf-8')
            print(f"🔐 Password received")

            # Test the password
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    first = next(m for m in zf.infolist() if not m.is_dir())
                    zf.read(first, pwd=zip_password)
            except RuntimeError:
                await status.edit_text("❌ **Wrong password!** Send the ZIP again.")
                if os.path.exists(zip_path): os.remove(zip_path)
                return

        except asyncio.TimeoutError:
            pending_passwords.pop(uid, None)
            await status.edit_text("⏰ **Timed out waiting for password.** Send ZIP again.")
            if os.path.exists(zip_path): os.remove(zip_path)
            return
    else:
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s @ {avg_str}\n\n"
            f"📝 **Send the domain name now:**\n"
            f"Example: `netflix.com` or `instagram.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )

    # ── Ask for domain ────────────────────────────────────────────────────────
    if zip_password:
        await status.edit_text(
            f"✅ **Password correct!**\n\n"
            f"📝 **Send the domain name now:**\n"
            f"Example: `netflix.com` or `instagram.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )

    loop = asyncio.get_event_loop()
    domain_future = loop.create_future()
    pending_domains[uid] = domain_future

    try:
        domain = await asyncio.wait_for(domain_future, timeout=60)
        print(f"🌐 DOMAIN: {domain}")
    except asyncio.TimeoutError:
        pending_domains.pop(uid, None)
        await status.edit_text("⏰ **Timed out.** Send ZIP again.")
        if os.path.exists(zip_path): os.remove(zip_path)
        return

    await status.edit_text(f"🔍 **Scanning for `{domain}` cookies...**")

    domain_prefix = domain.upper().split(".")[0]
    output_zip_path = f"/tmp/{uid}_{domain}_results.zip"
    total_matches = 0
    counter = 1
    scanned = 0

    try:
        cookie_files = collect_cookie_files_from_zip(zip_path, password=zip_password)
        scanned = len(cookie_files)
        print(f"📁 Found {scanned} cookie files")

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
                f"🎉 **{total_matches} valid cookies** for `{domain}`\n"
                f"📁 {scanned} files scanned | 📄 {counter-1} output files\n"
                f"📦 Sending ZIP...",
                parse_mode=enums.ParseMode.MARKDOWN
            )
            await client.send_document(
                message.chat.id,
                document=output_zip_path,
                caption=(
                    f"🍪 **{total_matches} cookies** for `{domain}`\n"
                    f"📄 `{domain_prefix}_1.txt` → `{domain_prefix}_{counter-1}.txt`\n"
                    f"✅ All garbage/binary lines filtered out"
                ),
                parse_mode=enums.ParseMode.MARKDOWN
            )
            await status.delete()
        else:
            await status.edit_text(
                f"❌ **No valid cookies** found for `{domain}`\n"
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
