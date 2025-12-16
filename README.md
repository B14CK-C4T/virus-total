# virusTotal.py

A simple Python CLI tool that collects intelligence data from **VirusTotal** using your **VirusTotal API key**.
It helps security researchers and bug bounty hunters extract useful indicators and save them into a clean, readable output file.

---

## ✨ Features

* Collects data from VirusTotal using the official API
* Extracts:

  * Detected URLs
  * Undetected URLs
  * IP addresses
  * Subdomains
* Saves all results into **one structured text file**
* CLI-based and automation-friendly

---

## 📦 Requirements

* Python **3.8+**
* VirusTotal API key
* Required Python packages:

  ```bash
  pip install requests
  ```

---

## 🔐 Initial Setup

Before using the tool, you **must initialize the configuration file**.

```bash
python virusTotal.py -init
```

This will:

* Prompt you for your VirusTotal API key
* Store it securely in a local config file

> ⚠️ Run `-init` **only once**, or again if you want to change the API key.

---

## 🚀 Usage

### Basic scan

```bash
python virusTotal.py -d example.com
```

### Save output to a file

```bash
python virusTotal.py -d example.com -o output.txt
```

---

## 🧾 Output Format

All collected data is written into **a single text file** in the following format:

```
[+] Detected URLs:
https://example.com/login

[+] IP Addresses:
192.168.1.1

[+] Subdomains:
api.example.com

[+] Undetected URLs:
https://example.com/archive.zip
```

---

## ⚠️ Usage Policy

* This tool uses the **VirusTotal API**
* Respect VirusTotal rate limits
* Use only on **authorized targets**
* Follow VirusTotal Terms of Service

---

## 📄 License

MIT License

---

## 👤 Author

**B14CK-C4T**
Cybersecurity Researcher | Ethical Hacker | Developer

---

Happy Hunting 🐍🔍
