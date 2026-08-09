# HexaCore

**HexaCore** is a powerful, lightweight, and modern memory scanning and manipulation tool built from scratch in **C++** using the **Win32 API**. Designed with a sleek dark theme and custom-drawn UI components, it provides advanced debugging and memory analysis features inspired by industry standards made with claude.

---

## 🚀 Features

* **Multi-Type Scanning:** Supports Binary, Byte, 2 Bytes, 4 Bytes, 8 Bytes, Float, Double, Strings, and Array of Bytes (AOB) with wildcard (`?` / `??`) support.
* **Scan Types:** Exact value, bigger/smaller than, value between, unknown initial value, increased/decreased value, and changed/unchanged value checks.
* **Multi-Level Pointer Scanner:** Resolve static pointers and multi-level pointer chains (up to 3 levels deep) mapped against process modules.
* **Memory Viewer & Hex Editor:** Real-time hex and ASCII memory dumping, manual byte editing, and region inspection.
* **Approximate Disassembler & NOP Tool:** Basic instruction length decoding and inline code patching (e.g., NOPing instructions via `0x90`).
* **Cheat Table & Value Freezing:** Save/load custom address tables, label addresses, and freeze values in real-time with adjustable intervals.
* **Process Manager:** Built-in process listing with automatic small icon extraction.

---

## 🛠️ Built With

* **Language:** C++ (Standard C++11/14)
* **Framework/API:** Win32 API, Common Controls (`Comctl32`), GDI / Owner-Draw UI

---

## 📥 Getting Started

1. Download the latest release or clone the repository.
2. Compile the project using a C++ compiler supporting Visual Studio or MinGW (Windows x64/x86).
3. Run **HexaCore.exe** (run as Administrator if target processes require elevated privileges).

---

## ⚠️ Disclaimer

HexaCore is developed strictly for educational purposes, software debugging, and single-player game analysis. The creator assumes no liability and is not responsible for any misuse or bans resulting from the use of this software. Use at your own risk.

---

## 🔒 Security

Hexacore is not a virus it is open source code you can analyze with AI and HexaCore not stealing y'all files or private informations like credit card or smth else!

---
