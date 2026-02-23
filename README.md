# SHA-256 File Verifier
A desktop SHA-256 verification toolkit with two implementations:
- Python + Tkinter version
- C++ Win32 + Windows CNG (BCrypt) version

Verify file integrity by comparing a calculated SHA-256 hash with a trusted hash.

## Features
- Browse and select a local file
- Calculate SHA-256 for the selected file
- Compare calculated hash against an expected hash
- Show clear match or mismatch result
- Dedicated `Read Hash` flow in the C++ app
- Input normalization and basic path hardening in the C++ app

## Tech Stack
| Variant | UI | Hashing | Build/Runtime |
|---|---|---|---|
| Python version | Tkinter | `hashlib.sha256` | Python 3 |
| C version | Win32 API | Windows CNG (`bcrypt`) | CMake + C++17 |

## Project Structure
```text
SHA-256_File_Verifier/
|-- python version/
|   `-- main.py               # Python Tkinter verifier
|-- C version/
|   |-- main.cpp              # C++ Win32 verifier
|   |-- CMakeLists.txt        # CMake build config
|   `-- build.ps1             # PowerShell build helper
`-- README.md                 # Project documentation
```

## GitHub Shortcuts
- Python folder: [`python version`](./python%20version/)
- C++ folder: [`C version`](./C%20version/)
- Python app file: [`python version/main.py`](./python%20version/main.py)
- C++ app file: [`C version/main.cpp`](./C%20version/main.cpp)
- Build script: [`C version/build.ps1`](./C%20version/build.ps1)
- CMake config: [`C version/CMakeLists.txt`](./C%20version/CMakeLists.txt)

## Clone and Open
```bash
git clone https://github.com/BnHany/SHA-256_File_Verifier
cd SHA-256_File_Verifier
```

## Getting Started

### Python Version
#### Prerequisites
- Python 3.10 or newer

#### Run
```powershell
cd "python version"
python main.py
```

### C Version
#### Prerequisites
- CMake 3.16+
- A C++17-compatible Windows compiler (MSVC or MinGW)
- PowerShell

#### Build
```powershell
cd "C version"
.\build.ps1 -Config Release
```

Optional clean rebuild:
```powershell
.\build.ps1 -Config Release -Clean
```

#### Run
After build, run one of:
```powershell
.\build\hash_verifier_gui.exe
.\build\Release\hash_verifier_gui.exe
```

## How to Use
1. Select a file.
2. Enter the trusted SHA-256 hash (64 hex characters).
3. Click verify:
- Python app: `Verify`
- C++ app: `Verify Hash Match`
4. Read the result dialog for match/mismatch.

## Notes
- SHA-256 hashes are displayed in lowercase hex.
- The C++ app performs extra path and file-type validation before hashing.

---

## Learn More / Documentation

If you want to understand the internal implementation, security considerations, and design decisions behind the SHA-256 File Verifier (both Python and C++ versions), refer to the detailed documentation below:

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/BnHany/SHA-256_File_Verifier)

This documentation is helpful for learners, security students, and developers who want to explore how SHA-256 verification is implemented across different stacks.

---

## Author

**BnHany**

Built with ❤️ to simplify file integrity verification for everyday users.
Contributions, issues, and feature requests are welcome.

---

## 📄 License

This project is licensed under the **MIT License**.  
Feel free to use, modify, and distribute. Please give proper credit and use responsibly.
