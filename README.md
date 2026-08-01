# 🦅 BOLAHawk

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</p>

An automated **API Security Testing Platform** designed to assess REST APIs against the **OWASP API Security Top 10**. BOLAHawk helps developers and security professionals identify common API security vulnerabilities, calculate CVSS risk scores, and generate professional security assessment reports through an intuitive web interface.

---

# 📑 Table of Contents

- Overview
- Key Features
- Technology Stack
- Architecture
- Project Structure
- Prerequisites
- Setup & Installation
- Configuration
- Running the Project
- Usage Guide
- Example Workflow
- Reports
- Supported Security Checks
- Deployment
- Screenshots
- Troubleshooting
- Ethical Use
- Roadmap
- Contributing
- License
- Author

---

# 📖 Overview

Modern applications rely heavily on APIs, making API security a critical aspect of software development. BOLAHawk automates the process of testing REST APIs against common security weaknesses by providing an easy-to-use dashboard, automated vulnerability detection, and detailed security reports.

The platform is intended for educational purposes, internal security assessments, and authorized penetration testing.

---

# ✨ Key Features

- Automated REST API security scanning
- Detection of OWASP API Top 10 vulnerabilities
- Broken Object Level Authorization (BOLA) testing
- Broken Function Level Authorization (BFLA) detection
- Mass Assignment testing
- JWT security validation
- Rate Limiting assessment
- CVSS v3.1 risk scoring
- Interactive React dashboard
- Professional HTML reports
- PDF report generation
- Scan history management
- Docker deployment support
- Modular scanning engine

---

# 🛠 Technology Stack

## Frontend

- React
- JavaScript
- HTML
- CSS

## Backend

- Python
- FastAPI

## Reporting

- HTML
- PDF

## Deployment

- Docker
- Docker Compose

---

# 🏗 Architecture

BOLAHawk consists of three primary components:

```
                +------------------------+
                |    React Dashboard     |
                +-----------+------------+
                            |
                            |
                            ▼
                +------------------------+
                |    FastAPI Backend     |
                +-----------+------------+
                            |
          +-----------------+-----------------+
          |                 |                 |
          ▼                 ▼                 ▼
     API Scanner      Report Generator   CVSS Calculator
                            |
                            ▼
                  HTML / PDF Reports
                            |
                            ▼
                  Target REST API
```

---

# 📁 Project Structure

```
BOLAHawk
│
├── backend/
│
├── frontend/
│
├── vulnerable-target-api/
│
├── docs/
│
├── docker-compose.yml
│
├── DEPLOYMENT.md
│
└── README.md
```

---

# 📋 Prerequisites

Before running the project, ensure you have one of the following environments configured.

## Option 1 (Recommended)

- Docker Desktop
- Docker Compose

## Option 2

- Python 3.11+
- Node.js 20+
- npm

---

# ⚙ Setup & Installation

## Clone the Repository

```bash
git clone https://github.com/Astik4/BOLAHawk.git

cd BOLAHawk
```

---

## Docker Installation (Recommended)

Build and start all services:

```bash
docker compose up --build
```

Once started:

| Service | URL |
|----------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Target API | http://localhost:5000 |

---

## Manual Installation

### Backend

```bash
cd backend

python -m venv .venv
```

Windows

```powershell
.venv\Scripts\activate
```

Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run backend

```bash
uvicorn app:app --reload
```

---

### Frontend

```bash
cd frontend

npm install

npm run dev
```

---

### Vulnerable Target API

```bash
cd vulnerable-target-api

pip install -r requirements.txt

python app.py
```

---

# ⚙ Configuration

By default, the application uses:

| Component | Default Address |
|------------|-----------------|
| Frontend | http://localhost:3000 |
| Backend | http://localhost:8000 |
| Target API | http://localhost:5000 |

Configuration can be modified depending on your deployment environment.

---

# 🚀 Running the Project

1. Start all required services.
2. Open the frontend dashboard.
3. Enter the target API URL.
4. Configure authentication if required.
5. Select the desired security checks.
6. Launch the scan.
7. Review scan findings.
8. Export reports.

---

# 📚 Usage Guide

### Step 1

Start the platform using Docker or manual installation.

### Step 2

Open the dashboard in your browser.

### Step 3

Enter the REST API endpoint you want to assess.

### Step 4

Configure authentication (if applicable).

### Step 5

Select the desired security modules.

### Step 6

Launch the scan.

### Step 7

Review detected vulnerabilities.

### Step 8

Generate HTML or PDF reports.

---

# 🔍 Example Workflow

```
Start Platform
      │
      ▼
Configure Target API
      │
      ▼
Launch Security Scan
      │
      ▼
Analyze Results
      │
      ▼
Generate Report
      │
      ▼
Review & Remediate
```

---

# 📄 Reports

Each completed scan generates professional security reports containing:

- Executive Summary
- Vulnerability Details
- Risk Severity
- CVSS Score
- Affected Endpoints
- Security Recommendations
- Remediation Guidance

Available formats:

- HTML
- PDF

---

# 🛡 Supported Security Checks

Current implementation includes support for:

- Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization (BFLA)
- Mass Assignment
- JWT Security Validation
- Missing Rate Limiting

The platform is designed to be modular, allowing additional security checks to be incorporated in future releases.

---

# 🚢 Deployment

The easiest deployment method is Docker.

```bash
docker compose up --build
```

For production deployments, services can also be deployed individually using container orchestration platforms or cloud infrastructure.

Refer to **DEPLOYMENT.md** for additional deployment guidance.

---

# 📸 Screenshots

## Dashboard

> Add dashboard screenshot here.

---

## Scan Results

> Add scan results screenshot here.

---

## Generated Report

> Add report screenshot here.

---

# 🛠 Troubleshooting

## Backend fails to start

- Verify Python version.
- Ensure dependencies are installed.
- Check backend logs.

---

## Frontend cannot connect

- Verify backend service is running.
- Check API endpoint configuration.

---

## Docker build issues

```bash
docker compose down

docker compose up --build
```

---

## Scan fails

- Verify the target API is reachable.
- Ensure proper authentication has been configured.
- Confirm network connectivity.

---

# ⚖ Ethical Use

BOLAHawk is intended exclusively for:

- Educational purposes
- Security research
- Authorized penetration testing
- Internal security assessments

Do **NOT** use this software against systems you do not own or do not have explicit authorization to test.

The author assumes no responsibility for misuse of this project.

---

# 📌 Roadmap

Future improvements may include:

- Additional OWASP API Top 10 coverage
- OpenAPI specification import
- API discovery
- Authentication profiles
- Scheduled scans
- CI/CD integration
- Multi-target scanning
- Plugin architecture
- Team collaboration features

---

# 🤝 Contributing

Contributions are welcome.

To contribute:

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/my-feature
```

3. Commit your changes

```bash
git commit -m "Add new feature"
```

4. Push the branch

```bash
git push origin feature/my-feature
```

5. Open a Pull Request

---

# 📄 License

This project is licensed under the MIT License.

See the LICENSE file for more information.

---

<p align="center">
Built with ❤️ for learning, API security research, and secure software development.
</p>
