# 🛡️ PhishGuard 2.0 - Enterprise Threat Defense

**PhishGuard** is a next-generation cybersecurity platform designed to detect and neutralize phishing attacks across multiple vectors. Leveraging advanced **Machine Learning**, **Computer Vision**, and **Natural Language Processing (NLP)**, it provides real-time protection against malicious URLs, QR codes, and social engineering emails.

![PhishGuard Banner](https://img.shields.io/badge/Status-Active-success?style=for-the-badge) ![Version](https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge) ![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)

---

## 🚀 Key Features

### 1. 🔍 Intelligent URL Scanning

- **Engine**: Hybrid detection using **XGBoost** (ML) and heuristic rules.
- **Accuracy**: Detection rate of ~88% on real-world datasets.
- **Analysis**: Inspects URL structure, domain reputation, and HTTPS validity.

### 2. 🖼️ Image & QR Code Analysis

- **Engine**: **OpenCV** + **Pillow**.
- **Capabilities**: detecting malicious QR codes embedded in images (Quishing).
- **Metadata**: Scans for hidden steganography or anomalous metadata.

### 3. 📧 Email Phishing Hunting

- **Engine**: **NLP** (Natural Language Processing) analysis.
- **Detection**:
 **Spoofing**: Compares `From` headers vs `Return-Path`.
- **Social Engineering**: Detects urgency, fear indicators (`"Action Required"`, `"Suspended"`).
 **Link Extraction**: Automatically scans all links within the email body.

### 4. 🌐 Holographic Threat Map

- **Visualization**: Interactive **3D Globe** (Three.js) displaying real-time threat origins.
- **Live Feed**: Pulsing indicators for active phishing campaigns globally.

### 5. 📖 Integrated Education

- **Contextual Learning**: "Learn Why" modules appear instantly when a threat is detected.
- **Knowledge Base**: Built-in guides on Spoofing, Social Engineering, and Digital Safety.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.9, FastAPI, Uvicorn
- **ML/AI**: Scikit-Learn, XGBoost, NumPy, Pandas
- **Vision**: OpenCV (Headless), Pillow
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism), JavaScript (ES6+)
- **Visualization**: Three.js (WebGL)
- **Database**: MongoDB (Local/Atlas)
- **Deployment**: Docker, Docker Compose

---

## 📦 Deployment

### Docker (Manual)

```bash
# Build (Run from root)
docker build -f backend/Dockerfile -t phishguard.

# Run
docker run -d -p 8000:8000 phishguard
```

## 🔧 Local Development

### 1. Backend Setup

```bash
# Requires Python 3.9 - 3.12 (Python 3.14 is not supported)
cd backend
pip install -r requirements.txt
uvicorn phishguard.api.app:app --reload
```

*The API will serve the frontend from `../frontend`*

### 2. Frontend

The frontend files (`index.html`, `style.css`) are in the `frontend/` folder.
You can edit them directly, and the running backend will serve the changes on refresh.

---

## 📡 API Documentation

PhishGuard exposes a RESTful API for integrations.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/scan/url` | Analyze a URL for phishing. |
| `POST` | `/scan/email` | Analyze raw email content. |
| `POST` | `/scan/image` | Upload image for QR/Steganography scan. |
| `GET` | `/stats/map` | Get real-time threat geolocation data. |
| `GET` | `/scans/history` | Retrieve recent scan logs. |

---

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Developed with ❤️ by Satyam Raghuvanshi
