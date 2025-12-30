<img width="2048" height="2048" alt="Logo" src="https://github.com/user-attachments/assets/57eaf053-c8da-477d-8b2d-d3fc24500ee2" />


# 🛡️ AD-ENUM

### Interactive Active Directory Enumeration & Attack Framework

**AD-ENUM** is an **all-in-one, menu-driven Active Directory attack and enumeration toolkit** built for **learning, labs, red-team practice, and certification preparation**.

It combines **Responder, NTLM Relay, IPv6 attacks, password spraying, Impacket shells, enumeration, and hash cracking** into a **single interactive terminal interface** with **live output and automatic loot management**.

> Designed for **clarity, structure, and real-world AD attack flow**, not noisy one-off scripts.

---

## ✨ Key Highlights

* 🧠 **Attack-Aware Workflow**

  * Smart **Attack Advisor** recommends next steps based on open ports & security posture
* 🖥️ **Full Interactive TUI**

  * Live split-screen monitoring using `curses`
  * Real-time Responder + Relay output
* 🔄 **End-to-End Attack Chain**

  * Poison → Relay → Shell → Crack → Enumerate
* 📁 **Automatic Loot Management**

  * Timestamped loot directories per run
* 🔐 **Built for Modern AD**

  * SMB signing checks
  * IPv6 / LDAP relay support
* 🧪 **Exam & Lab Friendly**

  * Clean output
  * No unnecessary noise
  * PJPT / CRTP / OSCP-style workflows

---

## 📋 Features Overview

### 1️⃣ Attack Advisor (Smart Mode)

* Scans target ports
* Detects:

  * SMB signing status
  * LDAP / Kerberos availability

---

### 2️⃣ Responder Module

* LLMNR / NBT-NS poisoning
* Live monitoring

---

### 3️⃣ SMB Relay (NTLM Relay)

* Automatic scan for **SMB signing NOT required**
* Generates vulnerable target list
* Modes:

  * Dump SAM
  * Interactive shell (`-i`)
  * Custom command execution (`-c`)
* Live **dual-pane UI**:

  * Responder output
  * NTLMRelayX output

---

### 4️⃣ Password Spraying

* Powered by **NetExec / CrackMapExec**
* Supports:

  * Single username/password
  * Username file
  * Password file
* Uses `--continue-on-success` to find **all valid creds**

---

### 5️⃣ Impacket Shell Launcher

* Quick access to:

  * `psexec`
  * `wmiexec`
  * `smbexec`
* Authentication:

  * Plaintext password
  * NTLM hashes

---

### 6️⃣ IPv6 DNS Takeover & LDAP Relay

* Fully automated:

  * `mitm6`
  * `ntlmrelayx` (LDAP)
* Live curses interface
* Detects:

  * User creation
  * Loot drops
* Stores all results automatically

---

### 7️⃣ Enumeration Module

* SMB:

  * `nmap smb-enum-*`
  * `smbclient`
* LDAP:

  * Auto-detects 389 vs 636
* DNS:

  * DC SRV record discovery

---

### 8️⃣ Hash Cracking Engine

* Paste hash **or** load from file
* Auto-detects hash type:

  * NTLM
  * NTLMv1 / NTLMv2
  * Kerberos AS-REP
  * Kerberoast
  * DCC2
* Uses `hashcat` with live status

---

### 9️⃣ Loot Viewer

* Browse all captured data directly from the menu

---

## 🧰 Tools Used Internally

This framework integrates and orchestrates the following tools:

* `Responder`
* `Impacket (ntlmrelayx, psexec, wmiexec, smbexec)`
* `mitm6`
* `NetExec / CrackMapExec`
* `nmap`
* `hashcat`
* `ldapsearch`
* `smbclient`

---

## ⚙️ Requirements

### Python

* Python 3.9+

### Required Tools

```bash
sudo apt install responder mitm6 nmap hashcat ldap-utils smbclient netexec impacket-scripts
```

---

## 🚀 Installation & Usage

```bash
git clone https://github.com/<your-username>/AD-ENUM.git
cd AD-ENUM
sudo python3 ad_enum.py
```

> ⚠️ **Must be run as root** (network poisoning & relay require it)

---

## 📂 Loot Structure

```
AD_ENUM_loot_YYYYMMDD_HHMMSS/
├── responder.log
├── targets.txt
├── spray_results.log
├── enum_*.log
├── captured.hash
└── ntlmrelayx loot files
```

Each run creates a **new isolated loot directory** automatically.

---

## 🎯 Intended Use

* Active Directory labs
* Red-team practice
* Learning NTLM relay & AD attack chains

> ❗ **For educational and authorized testing only**

---

## 👤 Author

**Akhil Bangaru**


## 📌 Roadmap

* Kerberoasting automation
* BloodHound ingestion
* Report generation
* Modular plugin system

---
