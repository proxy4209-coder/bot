import os
import re
import time
import json
import sqlite3
import urllib.parse
import tempfile
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
    "cookies.sqlite", "cookies.db", "cookies.json",
    "cookiedata", "cookiedata.txt", "cookiedata.sqlite",
    "netscape cookies.txt", "netscape_cookies.txt",
    "chrome_cookies", "firefox_cookies", "edge_cookies",
    "localstorage.json", "local_storage.json",
}

COOKIE_KEYWORDS = ["cookie", "cookies", "cookiedata", "netscape", "browser_cookies"]

def is_cookie_file(fname: str) -> bool:
    """
    Enhanced cookie file detection
    """
    fname_lower = os.path.basename(fname).lower().strip()
    
    # Check exact matches
    if fname_lower in COOKIE_FILENAMES_EXACT:
        return True
    if fname_lower.replace(" ", "_") in COOKIE_FILENAMES_EXACT:
        return True
    
    # Check for cookie keywords anywhere in filename
    for kw in COOKIE_KEYWORDS:
        if kw in fname_lower:
            return True
    
    # Check for common cookie file patterns
    cookie_patterns = [
        r'cookie',
        r'cookies?\.(txt|sqlite|db|json|dat)',
        r'netscape',
        r'browser_cookies',
        r'default_cookies',
        r'chrome.*cookies',
        r'firefox.*cookies',
        r'edge.*cookies',
        r'local[\s_]?storage',
    ]
    
    for pattern in cookie_patterns:
        if re.search(pattern, fname_lower):
            return True
    
    # Check file extensions that might contain cookies
    cookie_extensions = ['.txt', '.sqlite', '.db', '.json', '.dat', '.log']
    for ext in cookie_extensions:
        if fname_lower.endswith(ext) and any(kw in fname_lower for kw in ['cookie', 'cookies', 'storage']):
            return True
    
    return False

def is_archive(fname: str) -> bool:
    lower = fname.lower()
    return lower.endswith('.zip') or lower.endswith('.rar') or lower.endswith('.7z') or lower.endswith('.tar') or lower.endswith('.gz')

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

def test_archive_password(path: str, password: bytes) -> bool:
    try:
        if path.lower().endswith('.rar'):
            with rarfile.RarFile(path, 'r') as rf:
                rf.setpassword(password.decode('utf-8', errors='ignore'))
                first = next(m for m in rf.infolist() if not m.is_dir())
                try:
                    rf.read(first)
                except rarfile.BadRarFile:
                    return False
                except Exception:
                    pass
        else:
            with zipfile.ZipFile(path, 'r') as zf:
                first = next(m for m in zf.infolist() if not m.is_dir())
                try:
                    zf.read(first, pwd=password)
                except RuntimeError as e:
                    if 'password' in str(e).lower():
                        return False
                except Exception:
                    pass
        return True
    except Exception:
        return True

# ── Domain matching ───────────────────────────────────────────────────────────
def domain_matches(cookie_domain: str, search_domain: str) -> bool:
    """
    Enhanced domain matching
    """
    cookie_domain = cookie_domain.lower().lstrip(".")
    search_domain = search_domain.lower().lstrip(".")
    
    # Exact match
    if cookie_domain == search_domain:
        return True
    
    # Domain/subdomain matches
    if cookie_domain.endswith("." + search_domain):
        return True
    if search_domain.endswith("." + cookie_domain):
        return True
    
    # Substring matching
    if search_domain in cookie_domain:
        return True
    if cookie_domain in search_domain:
        return True
    
    # Check for common domain variations
    search_parts = search_domain.split('.')
    cookie_parts = cookie_domain.split('.')
    
    # If it's a subdomain of the search domain
    if len(cookie_parts) > len(search_parts) and cookie_parts[-(len(search_parts)):] == search_parts:
        return True
    
    return False

# ── Content validation ────────────────────────────────────────────────────────
def is_valid_cookie_content(content: bytes) -> bool:
    """
    Check if content has any readable cookie-like data
    """
    try:
        # Try to decode as text
        text = content.decode('utf-8', errors='ignore')
        
        # Check for domain patterns
        if re.search(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text):
            # Check for tab-separated format
            lines = text.splitlines()
            for line in lines[:20]:  # Check first 20 lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '\t' in line and len(line.split('\t')) >= 3:
                    return True
                # Check for JSON structure
                if line.startswith(('{', '[')) and any(kw in line.lower() for kw in ['domain', 'name', 'value']):
                    return True
        
        # Check for SQLite header
        if content.startswith(b'SQLite format'):
            return True
            
        return False
    except:
        return False

# ── Netscape cookie parser ────────────────────────────────────────────────────
def parse_netscape_cookies(text: str, domain_filter: str):
    """
    Parse cookies in Netscape format
    """
    domain_filter = domain_filter.strip().lower().lstrip(".")
    results = []
    
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Try tab-separated first
        parts = line.split("\t")
        if len(parts) < 7:
            # Try space-separated
            parts = re.split(r"\s+", line, maxsplit=6)
        
        if len(parts) < 7:
            continue
            
        domain, flag, path, secure, expiry, name, value = parts[:7]
        
        # Clean domain for matching
        domain_clean = domain.lower().lstrip(".")
        
        # Use enhanced domain matching
        if domain_matches(domain_clean, domain_filter):
            # Ensure proper tab format
            result_line = "\t".join([domain, flag, path, secure, expiry, name, value])
            results.append(result_line)
    
    return results

# ── SQLite cookie parser ──────────────────────────────────────────────────────
def parse_sqlite_cookies(content: bytes, domain_filter: str) -> list:
    """
    Parse cookies from SQLite database files (Chrome, Firefox, Edge)
    """
    results = []
    temp_file = None
    
    try:
        # Write to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite', mode='wb') as tmp:
            tmp.write(content)
            temp_file = tmp.name
        
        # Connect to SQLite
        conn = sqlite3.connect(temp_file)
        cursor = conn.cursor()
        
        # Try common cookie table schemas
        queries = [
            # Chrome/Chromium
            "SELECT host_key, path, is_secure, expires_utc, name, value FROM cookies",
            # Firefox
            "SELECT domain, path, isSecure, expiry, name, value FROM moz_cookies",
            # Generic
            "SELECT host, path, secure, expires, name, value FROM cookies",
            "SELECT domain, path, secure, expiry, name, value FROM cookie",
            # Edge/Others
            "SELECT domain, path, secure, expiration, name, value FROM cookies",
        ]
        
        for query in queries:
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
                if rows:
                    for row in rows:
                        if len(row) >= 6:
                            domain, path, secure, expiry, name, value = row[:6]
                            if domain and name and domain_matches(domain, domain_filter):
                                flag = "TRUE" if domain.startswith('.') else "FALSE"
                                secure_flag = "TRUE" if secure else "FALSE"
                                results.append(f"{domain}\t{flag}\t{path}\t{secure_flag}\t{expiry}\t{name}\t{value}")
                    if results:
                        break
            except:
                continue
        
        conn.close()
    except Exception as e:
        print(f"SQLite parse error: {e}")
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except:
                pass
    
    return results

# ── JSON cookie parser ────────────────────────────────────────────────────────
def parse_json_cookies(content: bytes, domain_filter: str) -> list:
    """
    Parse cookies from JSON format
    """
    results = []
    try:
        text = content.decode('utf-8', errors='ignore')
        # Try to clean the text (remove BOM, etc.)
        text = text.lstrip('\ufeff').strip()
        
        # Try to find JSON object in text (in case there's surrounding text)
        json_match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
        if json_match:
            text = json_match.group(1)
        
        data = json.loads(text)
        
        # Handle various JSON structures
        cookies_list = []
        if isinstance(data, list):
            cookies_list = data
        elif isinstance(data, dict):
            # Try common keys
            for key in ['cookies', 'cookie', 'data', 'items', 'rows', 'entries']:
                if key in data and isinstance(data[key], list):
                    cookies_list = data[key]
                    break
            else:
                # Maybe it's a single cookie object
                if 'name' in data and 'value' in data:
                    cookies_list = [data]
                else:
                    # Try to find any array in the dict
                    for value in data.values():
                        if isinstance(value, list):
                            cookies_list = value
                            break
        
        for cookie in cookies_list:
            if isinstance(cookie, dict):
                # Extract fields with common names
                domain = cookie.get('domain', cookie.get('host', cookie.get('host_key', '')))
                path = cookie.get('path', '/')
                secure = cookie.get('secure', cookie.get('isSecure', cookie.get('is_secure', False)))
                expiry = cookie.get('expiry', cookie.get('expires', cookie.get('expirationDate', cookie.get('expires_utc', '0'))))
                name = cookie.get('name', '')
                value = cookie.get('value', cookie.get('val', ''))
                
                if domain and name and domain_matches(domain, domain_filter):
                    flag = "TRUE" if domain.startswith('.') else "FALSE"
                    secure_flag = "TRUE" if secure else "FALSE"
                    results.append(f"{domain}\t{flag}\t{path}\t{secure_flag}\t{expiry}\t{name}\t{value}")
    except Exception as e:
        print(f"JSON parse error: {e}")
    
    return results

# ── URL-encoded cookie parser ─────────────────────────────────────────────────
def parse_urlencoded_cookies(content: bytes, domain_filter: str) -> list:
    """
    Parse URL-encoded cookie data
    """
    results = []
    try:
        text = content.decode('utf-8', errors='ignore')
        
        # URL decode the text
        decoded = urllib.parse.unquote(text)
        
        # Try to parse as Netscape format first
        netscape_results = parse_netscape_cookies(decoded, domain_filter)
        if netscape_results:
            return netscape_results
        
        # Look for cookie patterns in the decoded text
        # Pattern: domain.com|domain|path|secure|expiry|name|value
        patterns = [
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[|\t]+\"?([A-Z]+)\"?[|\t]+([^|\t]+)[|\t]+\"?([A-Z]+)\"?[|\t]+(\d+)[|\t]+([^|\t]+)[|\t]+(.+?)(?=[|\n]|$)',
            r'domain[=:]\s*[\'"]([^\'"]+)[\'"][,\s]+name[=:]\s*[\'"]([^\'"]+)[\'"][,\s]+value[=:]\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, decoded, re.IGNORECASE)
            for match in matches:
                if len(match) >= 3:
                    # Try to construct Netscape format
                    domain = match[0] if '.' in match[0] else domain_filter
                    if domain_matches(domain, domain_filter):
                        name = match[-2] if len(match) > 2 else 'unknown'
                        value = match[-1]
                        results.append(f"{domain}\tFALSE\t/\tFALSE\t0\t{name}\t{value}")
    except Exception as e:
        print(f"URL decode error: {e}")
    
    return results

# ── Binary cookie extractor ───────────────────────────────────────────────────
def extract_cookies_from_binary(content: bytes, domain_filter: str) -> list:
    """
    Extract cookie-like patterns from binary/encoded data
    """
    results = []
    try:
        # Try to decode as text, ignoring errors
        text = content.decode('utf-8', errors='ignore')
        
        # Look for patterns that might be cookies
        patterns = [
            # Netscape-like pattern with various separators
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[|\s\t]+)(TRUE|FALSE)(?:[|\s\t]+)([^|\s\t]+)(?:[|\s\t]+)(TRUE|FALSE)(?:[|\s\t]+)(\d+)(?:[|\s\t]+)([^|\s\t]+)(?:[|\s\t]+)([^\n\r|]+)',
            
            # Domain with name=value pairs
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^a-zA-Z0-9]+([a-zA-Z0-9_]+)=([^;&\s\n\r]+)',
            
            # JSON-like structures
            r'["\']domain["\']\s*:\s*["\']([^"\']+)["\'][,\s]+["\']name["\']\s*:\s*["\']([^"\']+)["\'][,\s]+["\']value["\']\s*:\s*["\']([^"\']+)["\']',
            
            # Cookie string format
            r'([a-zA-Z0-9_]+)=([^;\s]+);\s*(?:domain=([^;\s]+))?',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) >= 2:
                    # Determine which part is domain
                    domain = None
                    name = None
                    value = None
                    
                    # Try to identify fields
                    for part in match:
                        if '.' in part and any(tld in part for tld in ['.com', '.org', '.net', '.io', '.co', '.uk', '.de', '.fr', '.ru', '.jp', '.br']):
                            domain = part
                        elif part and part not in ('TRUE', 'FALSE') and len(part) < 50:
                            if not name:
                                name = part
                            elif not value and name and part != name:
                                value = part
                    
                    if domain and name and value and domain_matches(domain, domain_filter):
                        results.append(f"{domain}\tFALSE\t/\tFALSE\t0\t{name}\t{value}")
    except Exception as e:
        print(f"Binary extraction error: {e}")
    
    return results

# ── Main cookie parser (chooses appropriate method) ───────────────────────────
def parse_cookies(content: bytes, filename: str, domain_filter: str) -> list:
    """
    Parse cookies from various formats based on file type and content
    """
    domain_filter = domain_filter.strip().lower().lstrip(".")
    filename_lower = filename.lower()
    
    # Quick validation - skip obviously invalid content
    if not is_valid_cookie_content(content):
        return []
    
    # Check file extension to determine parsing method
    if filename_lower.endswith(('.sqlite', '.db')):
        results = parse_sqlite_cookies(content, domain_filter)
        if results:
            print(f"✅ Parsed SQLite cookie file: {filename} ({len(results)} cookies)")
            return results
    
    elif filename_lower.endswith('.json'):
        results = parse_json_cookies(content, domain_filter)
        if results:
            print(f"✅ Parsed JSON cookie file: {filename} ({len(results)} cookies)")
            return results
    
    # Try Netscape format first (most common)
    try:
        text = content.decode('utf-8', errors='ignore')
        results = parse_netscape_cookies(text, domain_filter)
        if results:
            print(f"✅ Parsed Netscape cookie file: {filename} ({len(results)} cookies)")
            return results
    except:
        pass
    
    # Try URL-decoded format
    results = parse_urlencoded_cookies(content, domain_filter)
    if results:
        print(f"✅ Parsed URL-encoded cookie file: {filename} ({len(results)} cookies)")
        return results
    
    # Try JSON again (might be in binary)
    results = parse_json_cookies(content, domain_filter)
    if results:
        print(f"✅ Parsed JSON (binary) cookie file: {filename} ({len(results)} cookies)")
        return results
    
    # Try binary extraction as last resort
    results = extract_cookies_from_binary(content, domain_filter)
    if results:
        print(f"✅ Extracted cookies from binary file: {filename} ({len(results)} cookies)")
        return results
    
    print(f"⏭️ No cookies found in: {filename}")
    return []

# ── PHASE 1: Count all files inside archive ───────────────────────────────────
def count_archive_contents(path: str, password: bytes = None) -> dict:
    """Returns {total_files, total_folders, cookie_files, zip_files}"""
    total_files = 0
    total_folders = 0
    cookie_files = 0
    nested_zips = 0
    
    try:
        if path.lower().endswith('.rar') and RAR_SUPPORTED:
            with rarfile.RarFile(path, 'r') as rf:
                if password:
                    rf.setpassword(password.decode('utf-8', errors='ignore'))
                for m in rf.infolist():
                    if m.is_dir():
                        total_folders += 1
                    else:
                        total_files += 1
                        if is_cookie_file(m.filename):
                            cookie_files += 1
                        if is_archive(m.filename):
                            nested_zips += 1
        else:
            with zipfile.ZipFile(path, 'r') as zf:
                for m in zf.infolist():
                    if m.is_dir():
                        total_folders += 1
                    else:
                        total_files += 1
                        if is_cookie_file(m.filename):
                            cookie_files += 1
                        if is_archive(m.filename):
                            nested_zips += 1
    except Exception as e:
        print(f"⚠️ Count error: {e}")
    
    return {
        "total_files": total_files,
        "total_folders": total_folders,
        "cookie_files": cookie_files,
        "nested_zips": nested_zips,
    }

# ── PHASE 2: Extract with progress callback ───────────────────────────────────
def collect_cookie_files_from_zip(zip_path: str, password: bytes = None,
                                   depth: int = 0, max_depth: int = 6,
                                   progress_cb=None, counter=None):
    results = []
    if depth > max_depth:
        return results
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            members = zf.infolist()
            for member in members:
                if member.is_dir():
                    continue
                    
                fname = member.filename
                basename = os.path.basename(fname)
                
                # Handle nested archives
                if is_archive(basename):
                    try:
                        data = zf.read(member, pwd=password)
                        nested_path = f"/tmp/nested_{depth}_{int(time.time())}_{basename}"
                        with open(nested_path, 'wb') as f:
                            f.write(data)
                        nested = collect_from_archive(nested_path, password, depth + 1, max_depth, progress_cb, counter)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested error {basename}: {e}")
                
                # Check if it's a cookie file
                elif is_cookie_file(basename):
                    try:
                        content = zf.read(member, pwd=password)
                        results.append((fname, content))
                        print(f"📄 Found cookie file: {fname}")
                    except Exception as e:
                        print(f"⚠️ Read error {fname}: {e}")
                
                # tick progress
                if counter is not None:
                    counter[0] += 1
                    if progress_cb and counter[0] % 500 == 0:
                        progress_cb(counter[0])
                    
    except zipfile.BadZipFile:
        pass
    except Exception as e:
        print(f"⚠️ ZIP error: {e}")
    
    return results

def collect_cookie_files_from_rar(rar_path: str, password: str = None,
                                   depth: int = 0, max_depth: int = 6,
                                   progress_cb=None, counter=None):
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
                        nested = collect_from_archive(nested_path, password.encode() if password else None,
                                                      depth + 1, max_depth, progress_cb, counter)
                        results.extend(nested)
                        os.remove(nested_path)
                    except Exception as e:
                        print(f"⚠️ Nested error {basename}: {e}")
                
                elif is_cookie_file(basename):
                    try:
                        content = rf.read(member)
                        results.append((fname, content))
                        print(f"📄 Found cookie file: {fname}")
                    except Exception as e:
                        print(f"⚠️ Read error {fname}: {e}")
                
                if counter is not None:
                    counter[0] += 1
                    if progress_cb and counter[0] % 500 == 0:
                        progress_cb(counter[0])
                        
    except Exception as e:
        print(f"⚠️ RAR error: {e}")
    
    return results

def collect_from_archive(path: str, password: bytes = None, depth: int = 0,
                         max_depth: int = 6, progress_cb=None, counter=None):
    if path.lower().endswith('.rar'):
        pwd_str = password.decode('utf-8', errors='ignore') if password else None
        return collect_cookie_files_from_rar(path, pwd_str, depth, max_depth, progress_cb, counter)
    return collect_cookie_files_from_zip(path, password, depth, max_depth, progress_cb, counter)

# ── Telegram handlers ─────────────────────────────────────────────────────────
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
    await message.reply(
        "**🚀 Cookie Bot READY**\n\n"
        "🔹 Send ZIP or RAR\n"
        "🔹 Bot counts → extracts → scans\n"
        "🔹 Type domain e.g. `netflix.com`\n"
        "🔹 Get `NETFLIX_1.txt`, `NETFLIX_2.txt` ...\n\n"
        f"🔐 Password protected supported\n"
        f"{'✅ RAR supported' if RAR_SUPPORTED else '⚠️ RAR unavailable'}\n"
        f"📊 Multi-format parsing: Netscape, SQLite, JSON, URL-encoded",
        parse_mode=enums.ParseMode.MARKDOWN
    )

@app.on_message(filters.document)
async def doc_handler(client: Client, message: Message):
    doc_name = message.document.file_name if message.document else ""
    if doc_name.lower().endswith('.zip') or doc_name.lower().endswith('.rar'):
        await process_archive(client, message)
    else:
        await message.reply("❌ **ZIP or RAR only**", parse_mode=enums.ParseMode.MARKDOWN)

async def process_archive(client: Client, message: Message):
    doc = message.document
    fname = doc.file_name or "upload.zip"
    filesize = doc.file_size or 0
    uid = message.from_user.id
    is_rar = fname.lower().endswith('.rar')

    if is_rar and not RAR_SUPPORTED:
        await message.reply("❌ RAR not supported on this server.")
        return
    if filesize > 2e9:
        await message.reply("❌ Max 2GB")
        return

    ext = '.rar' if is_rar else '.zip'
    archive_path = f"/tmp/{uid}_{int(time.time())}{ext}"

    # ── DOWNLOAD ──────────────────────────────────────────────────────────────
    status = await message.reply("⬇️ **Downloading...**")
    dl_start = time.time()
    last_t = [time.time()]
    last_b = [0]

    async def dl_progress(current, total):
        now = time.time()
        if now - last_t[0] < 2.0:
            return
        dt = now - last_t[0]
        db = current - last_b[0]
        speed = db / dt if dt > 0 else 0
        eta = int((total - current) / speed) if speed > 0 else 0
        last_t[0] = now
        last_b[0] = current
        pct = current / total * 100
        bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
        spd = f"{speed/1e6:.1f} MB/s" if speed >= 1e6 else f"{speed/1e3:.0f} KB/s"
        eta_s = f"{eta//60}m {eta%60}s" if eta >= 60 else f"{eta}s"
        try:
            await status.edit_text(
                f"⬇️ **Downloading** `{fname}`\n"
                f"`[{bar}]` **{pct:.1f}%**\n"
                f"📦 {current/1e6:.1f} / {total/1e6:.1f} MB\n"
                f"⚡ **{spd}** | ⏱️ ETA: **{eta_s}**",
                parse_mode=enums.ParseMode.MARKDOWN
            )
        except: pass

    try:
        await client.download_media(message, file_name=archive_path, progress=dl_progress)
    except Exception as e:
        await status.edit_text(f"❌ Download failed: {e}")
        if os.path.exists(archive_path): os.remove(archive_path)
        return

    dl_elapsed = time.time() - dl_start
    avg_spd = filesize / dl_elapsed if dl_elapsed > 0 else 0
    avg_str = f"{avg_spd/1e6:.1f} MB/s" if avg_spd >= 1e6 else f"{avg_spd/1e3:.0f} KB/s"

    # ── PASSWORD ──────────────────────────────────────────────────────────────
    archive_password = None
    if is_encrypted(archive_path):
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` — {dl_elapsed:.1f}s @ {avg_str}\n\n"
            f"🔐 **Password protected!** Send password now:",
            parse_mode=enums.ParseMode.MARKDOWN
        )
        loop = asyncio.get_event_loop()
        pf = loop.create_future()
        pending_passwords[uid] = pf
        try:
            pwd_text = await asyncio.wait_for(pf, timeout=60)
            archive_password = pwd_text.encode('utf-8')
            if not test_archive_password(archive_path, archive_password):
                await status.edit_text("❌ **Wrong password!** Send archive again.")
                os.remove(archive_path)
                return
        except asyncio.TimeoutError:
            pending_passwords.pop(uid, None)
            await status.edit_text("⏰ Timed out. Send archive again.")
            os.remove(archive_path)
            return
        await status.edit_text(
            f"✅ **Password correct!**\n\n"
            f"📝 Send domain: e.g. `netflix.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )
    else:
        await status.edit_text(
            f"✅ **Downloaded** `{fname}` — {dl_elapsed:.1f}s @ {avg_str}\n\n"
            f"📝 Send domain: e.g. `netflix.com`",
            parse_mode=enums.ParseMode.MARKDOWN
        )

    # ── DOMAIN ────────────────────────────────────────────────────────────────
    loop = asyncio.get_event_loop()
    df = loop.create_future()
    pending_domains[uid] = df
    try:
        domain = await asyncio.wait_for(df, timeout=60)
    except asyncio.TimeoutError:
        pending_domains.pop(uid, None)
        await status.edit_text("⏰ Timed out. Send archive again.")
        os.remove(archive_path)
        return

    domain_prefix = domain.upper().split(".")[0]

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 1 — COUNT
    # ════════════════════════════════════════════════════════════════════════
    await status.edit_text(
        f"🔎 **Phase 1/3 — Counting files...**\n"
        f"📦 `{fname}`",
        parse_mode=enums.ParseMode.MARKDOWN
    )
    counts = count_archive_contents(archive_path, archive_password)
    total_files   = counts["total_files"]
    total_folders = counts["total_folders"]
    cookie_files_count = counts["cookie_files"]
    nested_zips   = counts["nested_zips"]

    await status.edit_text(
        f"📊 **Archive Contents:**\n"
        f"📁 Folders: **{total_folders:,}**\n"
        f"📄 Files: **{total_files:,}**\n"
        f"🍪 Cookie files: **{cookie_files_count:,}**\n"
        f"🗜️ Nested ZIPs/RARs: **{nested_zips:,}**\n\n"
        f"⏳ Starting extraction...",
        parse_mode=enums.ParseMode.MARKDOWN
    )
    await asyncio.sleep(1.5)

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 2 — EXTRACT (collect cookie files with progress)
    # ════════════════════════════════════════════════════════════════════════
    extract_start = time.time()
    extracted_counter = [0]
    last_extract_update = [0]

    # We run extraction in a thread so we can update progress from main loop
    cookie_files_result = []
    extraction_done = asyncio.Event()

    def run_extraction():
        def progress_cb(n):
            pass  # we update from async side
        result = collect_from_archive(archive_path, archive_password,
                                      counter=extracted_counter)
        cookie_files_result.extend(result)
        extraction_done.set()

    extract_thread = threading.Thread(target=run_extraction, daemon=True)
    extract_thread.start()

    # Show extraction progress while thread runs
    while not extraction_done.is_set():
        await asyncio.sleep(2)
        now = time.time()
        elapsed = now - extract_start
        n = extracted_counter[0]
        speed = n / elapsed if elapsed > 0 else 0
        remaining = total_files - n if total_files > 0 else 0
        eta = int(remaining / speed) if speed > 0 else 0
        pct = min(n / total_files * 100, 99.9) if total_files > 0 else 0
        bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
        eta_s = f"{eta//60}m {eta%60}s" if eta >= 60 else f"{eta}s"
        spd_s = f"{speed:.0f} files/s"
        try:
            await status.edit_text(
                f"📂 **Phase 2/3 — Extracting**\n"
                f"`[{bar}]` **{pct:.1f}%**\n"
                f"📄 Files: **{n:,}** / **{total_files:,}**\n"
                f"🚀 Speed: **{spd_s}**\n"
                f"⏳ ETA: **{eta_s}**\n"
                f"🍪 Cookie files found: **{len(cookie_files_result):,}**",
                parse_mode=enums.ParseMode.MARKDOWN
            )
        except: pass

    # Wait for extraction to complete
    await extraction_done.wait()

    # Delete input archive
    if os.path.exists(archive_path):
        os.remove(archive_path)

    cookie_files = cookie_files_result
    total_cookie_files = len(cookie_files)

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 3 — SCAN COOKIES (MULTI-FORMAT) - FIXED: Only create files with cookies
    # ════════════════════════════════════════════════════════════════════════
    output_zip_path = f"/tmp/{uid}_{domain}_results.zip"
    total_matches = 0
    output_file_counter = 1  # Renamed from 'counter' to avoid confusion
    scan_start = time.time()
    last_scan_update = [0]
    parsed_formats = {"netscape": 0, "sqlite": 0, "json": 0, "urlencoded": 0, "binary": 0}
    files_with_cookies = 0  # Track how many files actually contained cookies
    skipped_files = 0  # Track skipped files

    # Show initial scan bar immediately
    await status.edit_text(
        f"🔍 **Phase 3/3 — Scanning** `{domain}`\n"
        f"`[░░░░░░░░░░░░░░░░░░░░]` **0.0%**\n"
        f"📂 Files: **0** / **{total_cookie_files:,}**\n"
        f"🚀 Speed: **— files/s**\n"
        f"⏳ ETA: **—**\n"
        f"🍪 Cookies found: **0**",
        parse_mode=enums.ParseMode.MARKDOWN
    )

    try:
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf_out:
            for i, (orig_path, content_bytes) in enumerate(cookie_files):
                try:
                    # Quick validation - skip obviously invalid content
                    if not is_valid_cookie_content(content_bytes):
                        skipped_files += 1
                        print(f"⏭️ Skipping invalid/binary file: {orig_path}")
                        continue
                    
                    # Use multi-format parser
                    matches = parse_cookies(content_bytes, orig_path, domain)
                    
                    # ONLY create output file if matches were found
                    if matches and len(matches) > 0:
                        out_name = f"{domain_prefix}_{output_file_counter}.txt"
                        zf_out.writestr(out_name, "\n".join(matches))
                        total_matches += len(matches)
                        files_with_cookies += 1
                        output_file_counter += 1
                        
                        # Track format type
                        if orig_path.endswith(('.sqlite', '.db')):
                            parsed_formats["sqlite"] += 1
                        elif orig_path.endswith('.json'):
                            parsed_formats["json"] += 1
                        else:
                            parsed_formats["netscape"] += 1
                        
                        print(f"✅ Created {out_name} with {len(matches)} cookies from {orig_path}")
                    else:
                        print(f"⏭️ Skipped {orig_path} - no cookies found")
                            
                except Exception as e:
                    print(f"⚠️ Error processing {orig_path}: {e}")
                    skipped_files += 1

                # Update scan bar every 2s
                now = time.time()
                if now - last_scan_update[0] >= 2.0:
                    last_scan_update[0] = now
                    elapsed = now - scan_start
                    speed = (i + 1) / elapsed if elapsed > 0 else 0
                    remaining = total_cookie_files - (i + 1)
                    eta = int(remaining / speed) if speed > 0 else 0
                    pct = (i + 1) / total_cookie_files * 100 if total_cookie_files > 0 else 0
                    bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
                    eta_s = f"{eta//60}m {eta%60}s" if eta >= 60 else f"{eta}s"
                    try:
                        format_info = f"📊 Formats: Netscape:{parsed_formats['netscape']} SQLite:{parsed_formats['sqlite']} JSON:{parsed_formats['json']}"
                        await status.edit_text(
                            f"🔍 **Phase 3/3 — Scanning** `{domain}`\n"
                            f"`[{bar}]` **{pct:.1f}%**\n"
                            f"📂 Files: **{i+1:,}** / **{total_cookie_files:,}**\n"
                            f"🚀 Speed: **{speed:.0f} files/s**\n"
                            f"⏳ ETA: **{eta_s}**\n"
                            f"🍪 Cookies found: **{total_matches:,}** in **{files_with_cookies}** files\n"
                            f"{format_info}",
                            parse_mode=enums.ParseMode.MARKDOWN
                        )
                    except: pass

        # Final result - ONLY if we have matches
        if total_matches > 0:
            format_summary = f"\n📊 **Parsing Summary:**\n"
            format_summary += f"• Netscape: {parsed_formats['netscape']} files\n"
            format_summary += f"• SQLite: {parsed_formats['sqlite']} files\n"
            format_summary += f"• JSON: {parsed_formats['json']} files"
            if skipped_files > 0:
                format_summary += f"\n• Skipped (invalid): {skipped_files} files"
            
            await status.edit_text(
                f"✅ **Done! Scan complete**\n\n"
                f"🍪 **{total_matches:,} cookies** for `{domain}`\n"
                f"📄 **{files_with_cookies}** output files (from {total_cookie_files} scanned)\n"
                f"{format_summary}\n\n"
                f"📦 Sending ZIP...",
                parse_mode=enums.ParseMode.MARKDOWN
            )
            
            # Only send if we have files in the zip
            if files_with_cookies > 0:
                await client.send_document(
                    message.chat.id,
                    document=output_zip_path,
                    caption=(
                        f"🍪 **{total_matches:,} cookies** for `{domain}`\n"
                        f"📄 `{domain_prefix}_1.txt` → `{domain_prefix}_{files_with_cookies}.txt`\n"
                        f"📊 Scanned {total_cookie_files} files, found cookies in {files_with_cookies}\n"
                        f"📋 Formats: Netscape:{parsed_formats['netscape']} SQLite:{parsed_formats['sqlite']} JSON:{parsed_formats['json']}"
                    ),
                    parse_mode=enums.ParseMode.MARKDOWN
                )
                
                # Final update
                await status.edit_text(
                    f"✅ **All done!**\n\n"
                    f"🍪 **{total_matches:,} cookies** for `{domain}`\n"
                    f"📄 **{files_with_cookies}** files sent above ⬆️\n"
                    f"📂 Scanned **{total_cookie_files:,}** cookie files{format_summary}",
                    parse_mode=enums.ParseMode.MARKDOWN
                )
            else:
                await status.edit_text(
                    f"❌ **Error**: No valid cookies found to send",
                    parse_mode=enums.ParseMode.MARKDOWN
                )
        else:
            await status.edit_text(
                f"❌ **No cookies** found for `{domain}`\n"
                f"📂 Scanned **{total_cookie_files:,}** cookie files\n"
                f"⚠️ Skipped **{skipped_files}** invalid/binary files",
                parse_mode=enums.ParseMode.MARKDOWN
            )

    except Exception as e:
        print(f"❌ ERROR: {e}")
        await status.edit_text(f"❌ **Error**: {e}")

    finally:
        if os.path.exists(output_zip_path):
            os.remove(output_zip_path)

# ── Fake web server for Render ────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Cookie Bot is running!")
    
    def log_message(self, *args): pass

def run_server():
    server = HTTPServer(("0.0.0.0", 10000), Handler)
    print(f"🌐 Web server running on port 10000")
    server.serve_forever()

if __name__ == "__main__":
    print("🚀 Cookie Bot Starting...")
    print(f"📊 Multi-format cookie parser enabled")
    print(f"🔍 Supported formats: Netscape, SQLite, JSON, URL-encoded, Binary")
    threading.Thread(target=run_server, daemon=True).start()
    app.run()
