import confusables
import re
import os
import hashlib

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ========== CONFIGURATION ==========
INPUT_FILE = "urls.txt"
OUTPUT_FILE = "output.txt"
SHORTENED_FILE = "shortened.txt"
SHORT_DOMAIN = "https://sho.rt/"

# ========== TASK 1: HOMOGLYPH DETECTION ==========
def normalize_url(url):
    try:
        ascii_url = confusables.normalize(url)
        return ascii_url
    except Exception as e:
        return None

def detect_homoglyphs(url):
    normalized = normalize_url(url)
    if normalized is None:
        return "[⚠️ Suspicious]", "Invalid ASCII in A-label"
    if url != normalized:
        return "[⚠️ Suspicious]", f"Looks like: {normalized}"
    return "[✅ Safe]", ""

# ========== TASK 2: SHORTENING ==========
def shorten_url(url):
    # Simple hash-based shortening
    short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
    return SHORT_DOMAIN + short_hash

# ========== MAIN PROCESSING ==========
def process_urls():
    if not os.path.exists(INPUT_FILE):
        print(f"Input file '{INPUT_FILE}' not found.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as infile, \
         open(OUTPUT_FILE, "w", encoding="utf-8") as outfile, \
         open(SHORTENED_FILE, "w", encoding="utf-8") as shortfile:

        for line in infile:
            url = line.strip()
            if not url:
                continue

            status, details = detect_homoglyphs(url)
            outfile.write(f"{status}\t{url}\t{details}\n")

            if status == "[✅ Safe]":
                short_url = shorten_url(url)
                shortfile.write(f"{url} -> {short_url}\n")

    print(f"Processing complete.\nOutput saved to '{OUTPUT_FILE}' and '{SHORTENED_FILE}'.")

# ========== RUN SCRIPT ==========
if __name__ == "__main__":
    process_urls()
