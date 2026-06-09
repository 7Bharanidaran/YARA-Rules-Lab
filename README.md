# YARA Rules Lab

Custom YARA rules for malware detection, threat hunting, and detection engineering.

---

## Overview

YARA Rules Lab is a collection of custom YARA rules developed to identify suspicious patterns and malicious artifacts commonly encountered during malware analysis and threat hunting activities.

This repository demonstrates the practical use of YARA for detecting indicators associated with malicious PowerShell activity, downloaders, encoded payloads, web shells, ransomware, and other adversary techniques. It serves as a growing knowledge base for detection engineering and blue team operations.

---

## Objectives

* Develop reusable YARA rules.
* Understand YARA syntax and rule structure.
* Detect suspicious patterns and malicious artifacts.
* Explore malware analysis techniques.
* Build practical threat hunting skills.
* Support detection engineering and incident response activities.

---

## Environment

| Component        | Details                              |
| ---------------- | ------------------------------------ |
| Operating System | Kali Linux                           |
| YARA Version     | 4.5.5                                |
| Purpose          | Malware Detection and Threat Hunting |

---

## Repository Structure

```text
YARA-Rules-Lab
│
├── docs/
│
├── rules/
│   ├── powershell.yar
│   ├── downloader.yar
│   ├── base64_detection.yar
│   ├── webshell.yar
│   └── ransomware.yar
│
├── samples/
│   ├── benign.txt
│   └── malicious.txt
│
├── screenshots/
│
└── README.md
```

---

## Implemented Rules

### Suspicious PowerShell Detection

Detects suspicious PowerShell commands frequently observed in malicious scripts.

#### Indicators

* Invoke-Expression
* DownloadString

#### Example

```yara
rule Suspicious_PowerShell
{
    meta:
        description = "Detect suspicious PowerShell commands"
        severity = "medium"
        category = "PowerShell"

    strings:
        $a = "Invoke-Expression"
        $b = "DownloadString"

    condition:
        all of them
}
```

---

## Usage

Run the following command to scan a file:

```bash
yara rules/powershell.yar samples/malicious.txt
```

### Expected Output

```text
Suspicious_PowerShell samples/malicious.txt
```

---

## Applications

The techniques demonstrated in this repository can be applied to:

* Malware Analysis
* Threat Hunting
* Detection Engineering
* Incident Response
* Security Operations Center (SOC) Operations
* Digital Forensics
* File Classification

---

## Planned Rule Categories

This repository will continue to expand with additional rule sets covering:

* Downloader Detection
* Base64 Encoded Payload Detection
* Web Shell Detection
* PE Module Rules
* Ransomware Detection
* Office Document Malware
* Credential Theft Indicators
* Living-Off-The-Land Binaries (LOLBins)
* Persistence Mechanisms
* Memory Scanning
* Python and YARA Integration
* Advanced Threat Hunting Rules

---

## Skills Demonstrated

* YARA Rule Development
* Malware Analysis
* Threat Hunting
* Detection Engineering
* Blue Team Operations
* Incident Response
* Cybersecurity Documentation

---

## References

* YARA Documentation
  https://virustotal.github.io/yara/

* YARA GitHub Repository
  https://github.com/VirusTotal/yara

---



This repository is intended for educational and research purposes. The rules and sample files included are designed to demonstrate YARA functionality and should be used responsibly and in accordance with applicable laws and organizational policies.
