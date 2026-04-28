# 🛡️ WebScanner SaaS – AI-Powered Web Vulnerability Scanner

A production-ready web vulnerability scanning platform with intelligent detection, confidence scoring, AI-generated reports, retest analysis, and scheduled scans.

---

## 🚀 Features

### 🔍 Advanced Scanning Engine

- SQL Injection (SQLi) detection
- Cross-Site Scripting (XSS) detection
- Server-Side Request Forgery (SSRF) detection
- Remote Code Execution (RCE) detection
- File Upload vulnerability detection
- Security header analysis
- Information disclosure checks
- Exposure path detection
- Technology fingerprinting

### 🛡️ WAF Detection

- Passive WAF fingerprinting
- Detection via headers, response behavior, and anomalies
- Identifies protections like Cloudflare, ModSecurity, etc.

### 🧠 Intelligent Analysis

- Confidence scoring (confirmed, high, medium, low, info)
- Evidence-based findings
- Response diff analysis
- Payload tracking
- Context-aware detection (e.g., XSS context classification)
- False positive reduction

### 🔁 Retest System

- Re-run scans after fixes
- Compare previous vs new results
- Track:
  - ✅ Fixed
  - ⚠️ Still vulnerable
  - 🆕 New issues
  - 📌 Existing issues

### 📅 Scheduled Scans

- Weekly / monthly automated scans
- Continuous monitoring
- Automatic scan execution

### 📊 Dashboard & Analytics

- Risk score calculation
- Findings breakdown
- Severity distribution
- Confidence distribution
- Retest outcome tracking

### 📄 AI-Powered Reports

- LLM-generated vulnerability reports
- Executive summary
- Detailed findings
- Remediation guidance
- References (CVE, CWE, OWASP, Exploit-DB, KEV)

### 🧾 PDF Reporting

- Clean, structured reports
- Table-based formatting
- Enterprise-style output
- Downloadable reports

---

## 🏗️ System Architecture

```
Frontend (Next.js)
        ↓
Backend API (FastAPI)
        ↓
Scanner Engine + Services
        ↓
PostgreSQL Database
        ↓
LLM Provider (OpenRouter)
```

---

## ⚙️ Tech Stack

### Backend

- FastAPI
- SQLAlchemy (Async)
- Alembic
- PostgreSQL

### Frontend

- Next.js
- TypeScript
- Tailwind CSS

### AI / LLM

- OpenRouter
- GPT / LLM-based report generation

### Infrastructure

- Nginx (optional)
- Uvicorn
- Node.js

---

## 🛠️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/omental/webscanner-saas.git
cd webscanner-saas
```

### 2. Backend Setup

```bash
cd services/scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment

Create a `.env` file:

```bash
DATABASE_URL=postgresql+asyncpg://user:password@localhost/webscanner
OPENROUTER_API_KEY=your_api_key
OPENROUTER_MODEL=your_model
```

### 4. Run Migrations

```bash
alembic upgrade head
```

### 5. Start Backend

```bash
uvicorn app.main:app --reload
```

### 6. Frontend Setup

```bash
cd ../../apps/web
npm install
npm run dev
```

---

## 🧪 Usage

1. Add a target
2. Run a scan
3. View findings
4. Generate AI report
5. Download PDF report
6. Fix vulnerabilities
7. Run retest
8. Monitor via dashboard

---

## 🔄 Scanner Workflow

```
Target → Scan → Detection → Confidence Scoring
      → Evidence Collection → Report Generation
      → Fix → Retest → Comparison → Dashboard Update
```

---

## 📊 Example Outputs

- Risk Score Dashboard
- Vulnerability Findings Table
- AI Report (LLM)
- PDF Report
- Retest Comparison

---

## 🔐 Security Considerations

- Use responsibly on authorized targets only
- Avoid scanning systems without permission
- Protect API keys and credentials

---

## 🧠 Future Improvements

- Deeper fuzzing engine
- DOM-based XSS detection
- Advanced WAF bypass techniques
- Improved crawling depth
- Multi-tenant SaaS expansion

---

## 📜 License

This project is intended for educational and research purposes.

---

## 👨‍💻 Author

**JM Mubasshir Rahman**
Software Engineer & Security Researcher

---

## ⭐ Acknowledgements

- OWASP
- CVE / NVD databases
- OpenRouter LLM APIs

---

## 📬 Contact

For collaboration, research, or deployment inquiries.
