# Stenographic File Integrity Checker (Beginner Version)
# This is a simple project made by a beginner (for demo purpose).
# It hides SHA256 hash of a file inside a PNG image using Least Significant Bit (LSB).

from PIL import Image
import hashlib

# Function to make hash of a file
def make_hash(file_path):
    h = hashlib.sha256()
    f = open(file_path, "rb")
    data = f.read()
    h.update(data)
    f.close()
    return h.hexdigest()

# Function to hide hash in image (using red channel LSB only)
def hide_hash(cover_image, out_image, hash_text):
    img = Image.open(cover_image)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = ''.join(format(ord(c),'08b') for c in hash_text)
    new_pixels = []
    i = 0
    for r,g,b in pixels:
        if i < len(bits):
            r = (r & ~1) | int(bits[i])
            i += 1
        new_pixels.append((r,g,b))
    img.putdata(new_pixels)
    img.save(out_image)
    print("Hash hidden in", out_image)

# Function to read hash back
def read_hash(stego_image, length=64):
    img = Image.open(stego_image)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    bits = ""
    for r,g,b in pixels:
        if len(bits) < length*8:
            bits += str(r & 1)
    chars = [chr(int(bits[j:j+8],2)) for j in range(0,len(bits),8)]
    return ''.join(chars)

# Function to verify
def verify_file(target, stego):
    h1 = make_hash(target)
    h2 = read_hash(stego)
    if h1 == h2:
        print("File is OK (hash matches)")
    else:
        print("File changed (hash mismatch!)")
    return h1,h2

# --- Very basic Tkinter GUI ---
def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    def do_embed():
        target = filedialog.askopenfilename(title="Select file to protect")
        cover = filedialog.askopenfilename(title="Select cover image (png)")
        out = "stego.png"
        h = make_hash(target)
        hide_hash(cover, out, h)
        messagebox.showinfo("Done","Hash hidden in stego.png")

    def do_verify():
        target = filedialog.askopenfilename(title="Select file to check")
        stego = filedialog.askopenfilename(title="Select stego image")
        h1,h2 = verify_file(target, stego)
        messagebox.showinfo("Result", f"Current: {h1}\nHidden: {h2}")

    root = tk.Tk()
    root.title("File Integrity Checker (Beginner)")
    tk.Button(root, text="Embed Hash", command=do_embed).pack(pady=10)
    tk.Button(root, text="Verify File", command=do_verify).pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    print("Simple demo...")
    # Example: compute hash and hide in cover
    h = make_hash("sample_files/report.pdf")
    print("Hash:", h)
    hide_hash("sample_files/cover.png", "sample_files/stego.png", h)
    print("Now verifying...")
    verify_file("sample_files/report.pdf", "sample_files/stego.png")

    # Uncomment to run GUI
    # run_gui()
