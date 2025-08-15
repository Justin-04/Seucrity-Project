# Security Coursework Project — Vulnerable & Hardened Web Application

> **Disclaimer:** This project is for **educational and defensive security training** only.  
> All offensive techniques shown here must be executed **only** in a controlled lab environment that you own and have explicit permission to test.

---

## 📖 Introduction
This project was completed as part of the Information Systems Security course.  
It demonstrates a **full security testing and hardening workflow** — from building a deliberately vulnerable application, to implementing mitigations, and validating them through controlled attack simulations, network traffic analysis, and intrusion detection.

The project aims to:
- Understand and exploit common web application vulnerabilities.
- Apply secure coding practices to mitigate them.
- Deploy applications in a secure environment.
- Capture, decrypt, and analyze traffic.
- Detect malicious activity using IDS.

---

## 🎯 Objectives
1. **Implement** an intentionally vulnerable web application.
2. **Demonstrate** real-world attack techniques in a lab environment.
3. **Apply** security mitigations to remove vulnerabilities.
4. **Validate** improvements through testing and traffic analysis.
5. **Integrate** intrusion detection systems for ongoing monitoring.

---

## 🛠 Lab Setup

### Environment
- **Platform:** Local VM network (isolated, no internet exposure)
- **Tools & Technologies:**
  - **Docker & Docker Compose** — reproducible deployments.
  - **Node.js** + **MySQL** — backend development.
  - **Wireshark** — packet capture & TLS decryption.
  - **Burp Suite** — request interception & manipulation.
  - **Suricata IDS** — intrusion detection.
  - **Let’s Encrypt** — HTTPS configuration.

### Application Deployment
- Two applications:
  1. **Vulnerable App** — intentionally insecure to demonstrate attacks.
  2. **Secure App** — hardened with mitigations.
- Docker services included:
  - MySQL database
  - Vulnerable app → `http://localhost/`
  - Secure app → `https://localhost:8080/` (HTTPS via Let’s Encrypt)

### Network Monitoring
- All traffic routed through the lab network.
- Suricata configured with custom and ET Open rules.
- Wireshark configured with browser `SSLKEYLOGFILE` for HTTPS decryption.

---

## 📜 Methodology

### Phase 1 — Vulnerable Application
- Developed a basic web app with:
  - **SQL Injection (SQLi)** — concatenated SQL queries.
  - **Reflected Cross-Site Scripting (XSS)** — unsanitized user input in HTML.
  - **Weak Authentication** — plaintext password storage.
- **Attacks Performed**:
  - Login bypass via `' OR '1'='1`
  - XSS via `<script>alert(1)</script>`
  - Brute force with dictionary attacks

---

### Phase 2 — Secure Application
- Rebuilt app with:
  - **Prepared statements** for SQL queries.
  - **Input validation** and **output encoding**.
  - **Helmet** middleware for HTTP headers.
  - **Hashed passwords** (bcrypt).
  - **Rate limiting** for authentication endpoints.
- **Validation**:
  - All prior exploits failed.
  - Secure traffic confirmed via packet capture.

---

### Phase 3 — Traffic Analysis
- Captured HTTP & HTTPS traffic for both apps.
- Decrypted HTTPS using Let’s Encrypt certs and `SSLKEYLOGFILE`.
- Compared traffic to identify differences in vulnerability exposure.

---

### Phase 4 — Intrusion Detection
- Installed Suricata and enabled **Emerging Threats Open** rules.
- Created custom rules for:
  - SQL injection patterns.
  - Brute force detection.
  - SYN flood signals.
- Verified alerts in `/var/log/suricata/fast.log`.

---

## 🔐 Mitigations Summary

### Application Level
- Input validation
- Output encoding
- Parameterized queries
- Secure password hashing

### Server Level
- HTTPS via Let’s Encrypt with auto-renewal
- Redirect HTTP → HTTPS
- Hide server version info
- Limit TLS to strong cipher suites

### Network Level
- IDS monitoring (Suricata)
- Custom attack detection rules
- Firewall rules for SSH brute force prevention

---

## 🛡 Final Results
- No exploitable SQLi or XSS vulnerabilities remained.
- Brute force attempts were detected and rate-limited.
- TLS encryption prevented credential leakage.
- IDS alerted on all simulated attacks.

---

## 📦 Repository Contents
This public repository contains:
- **`README.md`** — Project summary and methodology.
- **`Project.pdf`** — Full coursework report with technical details, screenshots, and analysis.

*(All exploit scripts, raw packet captures, and sensitive configs are intentionally excluded.)*

---

## ⚖️ Ethics & Legal Notice
- All tests conducted in an isolated lab.
- No third-party systems were targeted.
- This project follows responsible disclosure and ethical hacking principles.

---

