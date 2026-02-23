import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file:\n{e}")
        return None

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def verify_hash():
    file_path = file_entry.get()
    trusted_hash = hash_entry.get().strip().lower()

    if not file_path or not trusted_hash:
        messagebox.showwarning("Warning", "Please select a file and enter a hash")
        return

    calculated_hash = calculate_sha256(file_path)
    if not calculated_hash:
        return

    if calculated_hash == trusted_hash:
        messagebox.showinfo(
            "Verified ✅",
            "File is authentic!\n\nSHA-256 matches."
        )
    else:
        messagebox.showerror(
            "Mismatch ❌",
            f"Hash does NOT match!\n\nCalculated:\n{calculated_hash}"
        )


root = tk.Tk()
root.title("SHA-256 File Verifier")
root.geometry("520x220")
root.resizable(False, False)

tk.Label(root, text="File Path:").pack(anchor="w", padx=10, pady=5)
file_frame = tk.Frame(root)
file_frame.pack(fill="x", padx=10)

file_entry = tk.Entry(file_frame, width=50)
file_entry.pack(side="left", padx=5)

browse_btn = tk.Button(file_frame, text="Browse", command=browse_file)
browse_btn.pack(side="right")

tk.Label(root, text="Trusted SHA-256 Hash:").pack(anchor="w", padx=10, pady=5)
hash_entry = tk.Entry(root, width=70)
hash_entry.pack(padx=10)

verify_btn = tk.Button(
    root,
    text="Verify",
    command=verify_hash,
    bg="#1f8f4a",
    fg="white",
    height=2
)
verify_btn.pack(pady=20)

root.mainloop()
