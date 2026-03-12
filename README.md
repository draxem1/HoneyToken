# HoneyToken 🍯🔐
A deception-based security project that tracks attackers who steal sensitive files.

HoneyToken is a defensive security system designed to detect, track, and analyze attackers after a system compromise. Instead of preventing the theft of sensitive data, HoneyToken uses a decoy file that appears valuable to attackers but secretly reports back telemetry about the attacker when accessed.

The goal is to gather intelligence such as IP address, ASN, geolocation, and attacker behavior while remaining stealthy.

---

## Project Goals

- Detect attackers that access or exfiltrate sensitive files
- Collect attacker telemetry automatically
- Forward attacker data to a centralized logging server
- Enable defenders to analyze attacker activity
- Provide a realistic cybersecurity project demonstrating detection engineering concepts

---

## Architecture
Attacker
|
v
Downloads "secret" file
|
v
HoneyToken Trigger
|
v
Telemetry Client (VM)
|
v
Logging Server
|
v
Threat Intelligence + Log Analysis

### Components

#### 1. Secret File
A decoy file placed in a location to attrack attackers

Examples:
- 'passwords.txt'
- 'database_backup.zip'

This project uses a private ssh key.

---

#### 2. Telemetry Client (Sensor)

Runs on the compromised VM and collects information on attacker

Collected data:

- Source IP
- Timestamp
- Hostname
- Username
- Commands executed
- ASN
- Geolocation

The data is then sent to a remote logging server.

---

### 3. Logging Server

Central server that recieves attacker telemtry.

Responsibilities:

- Accept connections from sensors
- Store logs
- Enrich attacker data
- Enable analysis

Example log entry:

> 2026-02-28T12:15:03Z
> IP: 185.220.101.3
> ASN: AS9009
> Country: Germany
> User: root
> Command: cat passwords.txt


---

## Example Data Collected

HoneyToken attempts to collect:

| Field | Description |
|-----|-----|
| IP Address | Attacker source IP |
| ASN | Autonomous System Number |
| Country | GeoIP location |
| Username | Account used |
| Hostname | Compromised system |
| Commands | Commands executed |
| Timestamp | Event time |

---

## Features

### Attacker Telemetry

The system captures attacker network and system information.

### Centralized Logging

All events are forwarded to a central logging server.

### Threat Intelligence

IP addresses can be enriched with:

- ASN lookup
- GeoIP
- Reputation databases

### Detection Engineering Practice

HoneySecret helps practice:

- log analysis
- attacker behavior analysis
- threat intelligence enrichment

---

## Technology Stack

| Component | Technology |
|---|---|
| Sensor | Rust |
| Logging Server | Rust |
| Transport | TCP |
| Log Processing | Rust / Bash |
| Threat Intel | ASN + GeoIP lookup |

Rust is used for performance, safety, and reliability.

---

## Future Improvements

Planned features:

- ASN lookup integration
- GeoIP enrichment
- command logging
- attacker session replay
- web dashboard for logs
- alerting system
- threat intelligence integration
- containerized deployment

---

## Learning Objectives

This project demonstrates concepts used by:

- SOC Analysts
- Detection Engineers
- Threat Hunters
- Incident Responders

Skills practiced:

- log analysis
- attacker telemetry
- detection engineering
- threat intelligence
- Rust systems programming

---

## Ethical Use

This project is intended for:

- security research
- cybersecurity education
- defensive security projects
- honeypot environments

Do **not deploy this on systems you do not own or have permission to monitor.**

---

## Author

Nick Legato

Cybersecurity & Detection Engineering Projects

---

## License

MIT License
