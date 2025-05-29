# 🔬 Python Remote Payload Executor (PoC)

> ⚠️ **Disclaimer**: This project is for educational and research purposes only. It demonstrates how a simple Python script could retrieve and execute remote code. Do **not** use this for malicious purposes. The author is not responsible for any misuse.

## 📜 Description

This script is a basic proof-of-concept showing how a remote payload can be fetched, decoded, and executed using Python. It illustrates behavior commonly seen in malware, such as:

- Communicating with a remote server (Command and Control-style)
- Fetching a Base64-encoded payload
- Decoding and executing the payload at runtime

This project is useful for understanding potential threats and developing defenses against similar techniques.

## ⚙️ Features

- Simple C2 communication using HTTP requests
- Base64 payload handling
- Dynamic execution via `exec()`
- Custom User-Agent spoofing

## 🛠️ Requirements

- Python 3.x
- `requests` library (install with `pip install requests`)

## 🚀 Usage

```bash
python main.py
