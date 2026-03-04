import os
import re
import time
import asyncio
import logging
import zipfile
from pyrogram import Client, filters, enums
from pyrogram.types import Message

BOT_TOKEN = "8663784484AAEDaOYGkT8cCnkBvVaCNEp4fjQL3pgDPlQ"
API_ID = 32201838
API_HASH = "5e270d2e3ed53eb5d37c8f8016ff4bcd"

app = Client("cookiebot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

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

@app.on_message()
async def main_handler(client: Client, message: Message):
    uid = message.from_user.id if message.from_user else 0
    
    # Safe document check
    doc_name = message.document.file_name if message.document and hasattr(message.document, 'file_name') else None
    doc_size = message.document.file_size if message.document and hasattr(message.document, 'file_size') else 0
    
    print(f"📨 RAW: User={uid} | Text='{message.text[:30] if message.text else 'None'}' | Doc={doc_name} ({doc_size})")
    
    # /start command
    if message.text and message.text.lower().startswith('/start'):
        await message.reply(
            "**🚀 Cookie Bot READY**\n\n"
            "🔹 Forward ZIP file\n"
            "🔹 Reply with `netflix.com`\n\n"
            "**⚡ Optimized download + memory scan**",
            parse_mode=enums.ParseMode.MARKDOWN
        )
        print("✅ /start OK")
        return
    
    # ZIP PROCESSING
    if message.document and doc_name and 'zip' in doc_name.lower():
        print(f"🎯 ZIP DETECTED: {doc_name}")
        print("🚀 PROCESSING ZIP...")
        await process_zip(client, message)
        return
    elif message.document:
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
    
    last_update = [0]
    async def progress(current, total):
        nonlocal status
        now = time.time()
        elapsed = now - last_update[0]
        if elapsed < 2.0: return
        
        speed = (current - last_update[0]) / elapsed if elapsed > 0 else 0
        eta = (total - current) / speed if speed > 0 else 0
        last_update[0] = now
        
        pct = current / filesize * 100
        bar = "█" * int(pct/5) + "░" * (20 - int(pct/5))
        
        try:
            await status.edit_text(
                f"⬇️ **{fname}**\n[{bar}] **{pct:.1f}%**\n"
                f"{current/1e6:.1f}/{filesize/1e6:.1f} MB\n"
                f"⚡ **{speed/1024:.1f} KB/s** ⏱️ ETA: {int(eta)}s",
                parse_mode=enums.ParseMode.MARKDOWN
            )
        except Exception as e:
            print(f"⚠️ Progress error: {e}")
    
    # 🔥 FIXED: No 'workers' parameter
    try:
        await client.download_media(message, file_name=zip_path, progress=progress)
        print("✅ DOWNLOAD COMPLETE")
    except Exception as e:
        print(f"❌ DOWNLOAD FAILED: {e}")
        await status.edit_text(f"❌ **Download failed**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)
        return
    
    elapsed = time.time() - start_time
    avg_speed = filesize / elapsed / 1024 if elapsed > 0 else 0
    print(f"⏱️ Download: {elapsed:.1f}s ({avg_speed:.1f} KB/s avg)")
    
    await status.edit_text(
        f"✅ **Downloaded** `{fname}`\n"
        f"⚡ **{elapsed:.1f}s** ({avg_speed:.1f} KB/s)\n\n"
        f"🔍 **Reply to this message** with domain:\n"
        f"`netflix.com` `instagram.com` etc."
    )
    
    # WAIT FOR DOMAIN (reply to THIS message)
    domain = ""
    max_wait = 30  # 30 seconds
    wait_start = time.time()
    
    while time.time() - wait_start < max_wait:
        try:
            async for msg in client.get_chat_history(message.chat.id, limit=10):
                if (msg.reply_to_message and msg.reply_to_message.id == message.id and 
                    msg.text and msg.from_user.id == uid and not msg.text.startswith('/')):
                    domain = msg.text.strip().lower()
                    print(f"🌐 DOMAIN: {domain}")
                    break
            if domain: break
            await asyncio.sleep(2)
        except:
            await asyncio.sleep(2)
    
    if not domain:
        await status.edit_text(
            "⏰ **No domain received in 30s**\n\n"
            "**Reply to download message** with domain\n"
            "or send `/start` to restart"
        )
        if os.path.exists(zip_path): os.remove(zip_path)
        return
    
    # MEMORY SCAN - NO EXTRACTION NEEDED!
    await status.edit_text(f"🔍 **Scanning `{domain}` cookies...**")
    print("🔍 MEMORY SCAN START")
    
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
            print("🧹 Cleanup OK")
        
        if total_matches > 0:
            output = f"🎉 **{total_matches} COOKIES** for `{domain}`\n"
            output += f"📊 **{scanned} files** scanned:\n\n"
            output += "\n\n".join(results[:3])
            if len(results) > 3:
                output += f"\n\n... **+{len(results)-3} more files**"
            await status.edit_text(output, parse_mode=enums.ParseMode.MARKDOWN)
            print(f"🎉 SUCCESS: {total_matches} cookies")
        else:
            await status.edit_text(
                f"❌ **No cookies** for `{domain}`\n"
                f"📁 **{scanned} files** scanned"
            )
            print("❌ No cookies found")
            
    except Exception as e:
        print(f"❌ PROCESS ERROR: {e}")
        await status.edit_text(f"❌ **Error**: {e}")
        if os.path.exists(zip_path): os.remove(zip_path)

if __name__ == "__main__":
    print("🚀 ULTRA Cookie Bot - DOWNLOAD FIXED!")
    print("📨 Forward ZIP → Reply domain → INSTANT RESULTS!")
    print("⚡ pip install tgcrypto for 10x faster downloads")
    app.run()
