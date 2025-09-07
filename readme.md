# Py-Gadgets

A collection of **Python gadgets** developed and maintained by me.  
Each tool focuses on **security, networking, and system utilities** with a lightweight, CLI-first design.

---

## 📦 Available Gadgets

### 🔍 QuickScope
- **Version:** v0.2.0  
- **Description:** Asynchronous TCP subnet & port scanner with optional banner grabbing.  
- **Features:**
  - IPv4/IPv6 support, hostnames, and CIDR ranges.
  - Scan common ports, custom lists, or ranges.
  - JSON / CSV / NDJSON / pretty text output.
  - Adjustable concurrency, timeouts, and port excludes.
  - Optional progress bar.
  - Safe banner grabbing for service hints.

---

### 🗄️ BigFiles
- **Version:** v0.2.0  
- **Description:** Find the largest files in a given directory tree.  
- **Features:**
  - Recursively scan directories.
  - Filter by minimum size (MB).
  - Show the top **N** biggest files.
  - Cross-platform (Linux, macOS, Windows).

---

### 🧬 Dupes
- **Version:** v0.2.0  
- **Description:** Detect duplicate files via SHA-256 hashing (with size pre-filter).  
- **Features:**
  - Group files by identical size + hash.
  - Recursively scan directories.
  - Print duplicate sets for easy cleanup.
  - Optionally filter by minimum file size.

---

## 🛠 Installation

Clone the repo and install locally:

```bash
git clone https://github.com/APonder-Dev/py-gadgets.git
cd py-gadgets
pip install -e .
```

Or install in an isolated environment:

```bash
pipx install .
```

---

## 🚀 Usage

Unified launcher:

```bash
pygadgets --help
pygadgets quickscope -- 192.168.1.0/24 -p 22,80,443
pygadgets bigfiles -- -p /var/log -n 30 -m 100
pygadgets dupes -- -p ~/Downloads
```

Direct per-tool commands:

```bash
quickscope example.com -p 1-1024 --json
bigfiles -p . -n 20 -m 50
dupes -p .
```

---

## 📂 Repo Structure

```
.
├─ src/py_gadgets/
│  ├─ __init__.py
│  ├─ __main__.py
│  ├─ cli.py              # unified CLI
│  └─ tools/              # individual gadgets
│     ├─ quickscope.py
│     ├─ bigfiles.py
│     └─ dupes.py
├─ tests/                 # unit tests per tool
├─ .github/workflows/     # GitHub Actions CI
├─ README.md
├─ LICENSE
└─ pyproject.toml
```

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE).

---

## ⭐ Support

- Issues & feature requests → [GitHub Issues](../../issues)  
- Pull requests welcome  
- Star ⭐ this repo if you find the tools useful!  

---

## 💖 Donation

If you find these gadgets helpful, please consider supporting development:

[💸 Donate via PayPal](https://www.paypal.com/donate/?business=6TUCF33LPY9K2&no_recurring=0&item_name=Development+and+Coding+Features&currency_code=USD)