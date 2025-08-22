# py-gadgets
A collection of unique, lightweight Python security & networking gadgets.  
**Created by [APonder.dev](https://aponder.dev)**

---

## 🔍 QuickScope
QuickScope is an asynchronous subnet and port scanner with basic banner grabbing.  
It is designed to be fast, lightweight, and easy to run directly from the command line.

### Features
- Supports single IPs and CIDR ranges
- Scan custom ports, ranges, or a set of common ports
- JSON or pretty text output
- Adjustable concurrency and timeouts
- Attempts simple banner grabbing for additional context

### Usage
```bash
# Scan a subnet with default common ports
python quickscope.py 192.168.1.0/24

# Scan a single IP with a custom port range
python quickscope.py 10.0.0.5 -p 1-1024

# Scan with higher concurrency and shorter timeout
python quickscope.py 192.168.0.10 -p 22,80,443 -c 2048 -t 0.8 --json
```

### Example Output
```
192.168.0.10
  22/tcp open  ← SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
  80/tcp open  ← Apache/2.4.52 (Ubuntu)
  443/tcp open
```

---

⚠️ **Disclaimer**: This tool is for educational and authorized environments only.  
Do not use QuickScope on networks you don’t own or have explicit permission to test.

---
