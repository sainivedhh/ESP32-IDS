# Sentinel DFA-IDS: Proactive Intrusion Detection

![Sentinel Console](https://img.shields.io/badge/Status-Operational-90006a?style=for-the-badge)
![ESP32](https://img.shields.io/badge/Hardware-ESP32-E7352C?style=for-the-badge&logo=espressif)
![DFA](https://img.shields.io/badge/Logic-Finite%20Automata-ff00bd?style=for-the-badge)

**Sentinel** is a high-performance Intrusion Detection System (IDS) that leverages the mathematical rigor of **Deterministic Finite Automata (DFA)** to secure network protocols. Unlike signature-based systems, Sentinel validates the *behavioral transitions* of sessions in real-time, providing an O(1) complexity guarantee for every packet analyzed.

---

## 🚀 Core Features

### 🧠 Mathematical Rigor
Every monitored protocol is mapped to a state-transition table. If a sequence of events deviates from the legal path, the system immediately identifies a **Protocol Violation** and transitions to a **Trap State**.

### 🛡️ Multi-Protocol Surveillance
- **TCP/IP**: Validates 3-way handshakes and flags fragmentation/SYN-flood anomalies.
- **HTTP/S**: Monitors API request sequencing and verb usage patterns.
- **MQTT**: Ensures IoT message broadcast stability and subscription integrity.

### 📊 Forensic Analytics
- **Live Incident Stream**: Real-time terminal output with sub-millisecond synchronization.
- **Forensic Records**: Persistent storage of intrusions and violations for audit deep-dives.
- **Protocol Isolation**: Absolute separation between protocol engines to prevent cross-triggering.

### 📟 Hardware Integration
Designed for the **ESP32**, the core engine provides hardware-level feedback via status LEDs and supports remote "Deploy DFA" commands from the web console.

---

## 🛠️ Tech Stack

- **Frontend**: Vanilla HTML5, Modern Javascript (ES6), TailwindCSS.
- **Styling**: Premium "Glassmorphism" Design with localized CSS variables.
- **Firmware**: C++ (Arduino/ESP32 framework) with parallel DFA processing.
- **Communication**: RESTful API requests with CORS-ready implementation.

---

## 📖 Getting Started

1. **Hardware Setup**: Upload the `esp32_ids.ino` firmware to your ESP32.
2. **Launch Console**: Open `index.html` in any modern browser.
3. **Link Hardware**: Enter the ESP32 IP address in the header.
4. **Deploy**: Click "Deploy DFA" to synchronize the state engines.

---

## 📂 Repository Structure

- `/esp32_ids`: Firmware core and DFA state-transition tables.
- `attacks.html`: Real-time simulation and attack recording console.
- `record.html`: Detailed forensic metrics and incident history.
- `main.js`: Core UI logic and synchronization engine.
- `api.js`: Hardware abstraction layer and communication logic.

---

> **Built for Academic Research & Network Security Excellence.**
> © Sai's Sentinel Core Systems // Secure By Design
