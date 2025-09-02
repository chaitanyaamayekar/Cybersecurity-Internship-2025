# Homoglyph URL Detection and Shortener Tool

## 🔍 Description
This project detects homoglyph-based phishing URLs — deceptive links that use similar-looking characters from different alphabets — and flags suspicious ones. It also shortens safe URLs for easier sharing.

## ✅ Features
- Detects homoglyph attacks using Unicode normalization
- Marks URLs as Safe or Suspicious
- Generates shortened URLs for safe links

## 📂 Files
- `homoglyph_url_tool.py` - Main script
- `urls.txt` - Input file containing URLs
- `output.txt` - Detection results
- `shortened.txt` - Shortened URLs
- `requirements.txt` - Python dependencies

## ▶️ How to Run
1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the tool:
   ```
   python homoglyph_url_tool.py
   ```

3. Check `output.txt` and `shortened.txt` for results.
