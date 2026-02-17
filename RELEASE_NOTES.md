# AutoPenTest-AI v1.0.0 Release Notes

**Release Date:** February 17, 2026  
**Status:** v1.0.0 Release Candidate  
**Codename:** Year 1 Complete

---

## 🎯 Highlights

AutoPenTest-AI is an agentic, fully-automated penetration testing framework that autonomously executes the entire penetration testing kill chain. Given a single target, the AI agent performs reconnaissance, exploitation, privilege escalation, post-exploitation, and report generation — all with human-in-the-loop safety controls.

**Target Success Rates:**
- HTB Easy: 100%
- HTB Medium: ≥95%
- HTB Hard: 90–95%

---

## ✨ Features

### Reconnaissance Pipeline (5 Phases)
- **Phase 1 — Domain Discovery:** Subdomain enumeration, DNS resolution
- **Phase 2 — Port Scanning:** Naabu integration, service detection, CDN detection
- **Phase 3 — HTTP Probing:** Technology detection (Wappalyzer-style), TLS inspection
- **Phase 4 — Resource Enumeration:** Katana crawler, GAU (URLs from archives), Kiterunner (API route brute-force)
- **Phase 5 — Vulnerability Scanning:** Nuclei template engine, CVE enrichment, MITRE ATT&CK mapping

### Neo4j Attack Surface Graph
- **17+ node types:** Domain, IP, Port, Service, Technology, Vulnerability, CVE, Session, Credential, and more
- **20+ relationship types** modeling the full attack surface
- Automated data ingestion from all reconnaissance phases
- Interactive 2D/3D graph visualization (react-force-graph)
- Natural language → Cypher query tool for the AI agent

### AI Agent (LangGraph ReAct)
- **LangGraph** state-machine agent with Think → Act → Observe loop
- **Multi-LLM support:** OpenAI GPT-4 and Anthropic Claude
- **Phase management:** INFORMATIONAL → EXPLOITATION → POST_EXPLOITATION
- **Memory persistence:** MemorySaver for multi-turn conversation history
- **WebSocket streaming:** Real-time thought and action streaming to the frontend
- **12 bound tools** across all phases

### MCP Tool Servers (Model Context Protocol)
- **Naabu Server** (Port 8000) — Port scanning
- **Curl Server** (Port 8001) — HTTP requests and probing
- **Nuclei Server** (Port 8002) — Template-based vulnerability scanning
- **Metasploit Server** (Port 8003) — Module search, execution, and session management
- **Query Graph Tool** — Natural language queries against Neo4j
- **Web Search Tool** — Tavily API integration for OSINT
- JSON-RPC 2.0 over HTTP protocol with centralized Tool Registry

### Exploitation Framework
- **Attack Path Router:** 10 attack categories with keyword-based intent classification
- **CVE Exploitation:** Metasploit module search and automated payload delivery
- **Brute Force:** 8 service types (SSH, FTP, SMB, HTTP, etc.) with wordlist management
- **Session Management:** Meterpreter and shell session tracking, Neo4j SessionNode storage
- **Risk-level assignment** and attack plan generation

### Post-Exploitation
- **File Operations:** Download, upload, and list files on compromised hosts
- **System Enumeration:** System info, users, network configuration, running processes
- **Privilege Escalation:** `getsystem`, suggest exploits, and execute escalation modules
- **Credential Storage:** Discovered credentials persisted as Neo4j CredentialNode

### Web Dashboard (Next.js 14)
- **Project management** — Create, configure, and track penetration tests
- **Real-time chat interface** — ChatWindow, MessageBubble, ChatInput components
- **Graph visualization** — Interactive attack surface explorer (2D/3D)
- **Scan results viewer** — Browse vulnerabilities, services, and findings
- **Progress streaming** — ProgressStream component with step tracking and status badges

### Security & Safety Features
- **Approval workflow** — ApprovalModal UI for dangerous operations (4 categories)
- **Phase-based tool access control** — Tools restricted by current agent phase
- **Stop/Resume controls** — Halt and restart agent execution at any time
- **Live guidance endpoint** — Redirect the AI agent in real time
- **Strict scope enforcement** and complete audit logging

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│               FRONTEND  (Next.js 14 / TypeScript)       │
│   Dashboard · Graph Viz · Chat · ApprovalModal · Stream │
└────────────────────────┬────────────────────────────────┘
                         │  REST API + WebSocket
┌────────────────────────┴────────────────────────────────┐
│               BACKEND  (FastAPI / Python 3.11+)         │
│   API Layer · LangGraph Agent · Attack Path Router      │
│   Tool Registry (phase-gated) · Approval Engine         │
└─────────┬──────────────────────────────────┬────────────┘
          │                                  │
  ┌───────┴────────┐              ┌──────────┴──────────┐
  │  DATA LAYER    │              │  MCP TOOL SERVERS    │
  │  PostgreSQL 16 │              │  Naabu  :8000        │
  │  Neo4j 5.15    │              │  Curl   :8001        │
  │                │              │  Nuclei :8002        │
  │                │              │  Msf    :8003        │
  └────────────────┘              └──────────┬──────────┘
                                             │
                                  ┌──────────┴──────────┐
                                  │  KALI TOOL SANDBOX   │
                                  │  Nmap, Nuclei, SQLMap │
                                  │  Metasploit, LinPEAS  │
                                  └─────────────────────┘
```

### Docker Containers (6 services)

| Container | Image / Build | Purpose |
|-----------|--------------|---------|
| `autopentestai-postgres` | `postgres:16-alpine` | Relational data (users, projects, config) |
| `autopentestai-neo4j` | `neo4j:5.15-community` | Attack surface graph database |
| `autopentestai-backend` | Custom (Python 3.11) | FastAPI REST API + AI Agent |
| `autopentestai-frontend` | Custom (Node 20) | Next.js 14 web dashboard |
| `autopentestai-kali-tools` | Custom (Kali) | Security tools + MCP servers |
| `autopentestai-recon` | Custom | Dedicated reconnaissance tools |

### Network Segmentation

| Network | Subnet | Access |
|---------|--------|--------|
| `db-network` | 172.20.1.0/24 | Internal only — databases |
| `backend-network` | 172.20.2.0/24 | Backend ↔ databases ↔ tools |
| `frontend-network` | 172.20.3.0/24 | Frontend ↔ backend |
| `tools-network` | 172.20.4.0/24 | Isolated security tools |

### Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Frontend** | Next.js 14 (App Router), TypeScript, Tailwind CSS, shadcn/ui, TanStack Query, react-force-graph |
| **Backend** | FastAPI, Python 3.11+, Prisma ORM, JWT auth, WebSocket/SSE |
| **Databases** | PostgreSQL 16, Neo4j 5.15 (APOC plugin) |
| **AI / Agent** | LangGraph, LangChain, OpenAI GPT-4, Anthropic Claude |
| **Security Tools** | Nmap, Naabu, Nuclei, SQLMap, Metasploit, Katana, GAU, Kiterunner, LinPEAS/WinPEAS |
| **Infrastructure** | Docker & Docker Compose, GitHub Actions CI/CD, pytest, Jest |

---

## 🚀 Getting Started

### Prerequisites
- Docker Desktop (or Docker Engine + Docker Compose)
- Node.js 22+
- Python 3.11+
- Git

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/BitR1ft/FYP.git
cd FYP

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys and passwords

# 3. Launch all services
docker-compose up -d

# 4. Access the application
#    Frontend:     http://localhost:3000
#    Backend API:  http://localhost:8000
#    API Docs:     http://localhost:8000/docs
#    Neo4j Browser: http://localhost:7474
```

### Development Mode

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend
npm install && npm run dev
```

---

## ⚠️ Known Issues & Limitations

| # | Limitation | Impact | Planned Mitigation |
|---|-----------|--------|-------------------|
| 1 | Keyword-based intent classification | May misclassify ambiguous inputs | ML classifier (Year 2) |
| 2 | First-match classification only | Returns first matching category | Confidence scoring (Year 2) |
| 3 | No multi-target campaign support | One target at a time | Campaign orchestration (Year 2) |
| 4 | No automated report generation | Manual result review required | Report engine (Year 2) |
| 5 | API authentication not enforced | Endpoints unprotected in v1 | Auth middleware (Year 2) |
| 6 | Limited automated tool chaining | Manual tool sequencing | Automated chaining (Year 2) |
| 7 | No rate limiting | Potential API abuse | Rate limiter (Year 2) |
| 8 | Multi-tenancy documented only | Not fully enforced | Full isolation (Year 2) |

**Production Readiness:**
- ✅ **Development / Lab Testing** — Ready
- ⚠️ **Production** — Requires additional hardening (auth, rate limiting, audit logging, TLS)

---

## 🆕 What's New in v1.0.0 (Month 12)

Month 12 completes Year 1 by delivering the full exploitation subsystem:

- **Attack Path Router** — 10 attack categories with intent classification, risk-level assignment, and plan generation
- **ExploitExecuteTool** — CVE exploitation via Metasploit with payload configuration and session detection
- **BruteForceTool** — Multi-service brute force (8 service types) with wordlist management
- **SessionManagerTool** — Meterpreter/shell session tracking with Neo4j `SessionNode`
- **FileOperationsTool** — Download, upload, and list files on compromised targets
- **SystemEnumerationTool** — Sysinfo, users, network, and process enumeration
- **PrivilegeEscalationTool** — `getsystem`, suggest, and exploit actions
- **Neo4j CredentialNode** — Discovered credentials persisted in the graph
- **ApprovalModal** (frontend) — Human-in-the-loop confirmation for dangerous operations
- **ProgressStream** (frontend) — Real-time step tracking with status badges
- **4 new API endpoints** — `/agent/stop`, `/agent/resume`, `/agent/guide`, `/agent/approve`
- **Phase-based tool access control** — Tools gated to EXPLOITATION and POST_EXPLOITATION phases
- **Integration test suite** — 6 test classes covering the full exploitation pipeline

---

## 📊 Year 1 Cumulative Statistics

| Metric | Value |
|--------|-------|
| Development Duration | 12 months (365 days) |
| Total Files Created | 100+ |
| Total Lines of Code | 15,000+ |
| Backend (Python) | 8,000+ lines |
| Frontend (TypeScript) | 5,000+ lines |
| Documentation | 2,000+ lines |
| MCP Servers | 4 |
| Agent Tools | 12 |
| Neo4j Node Types | 17+ |
| API Endpoints | 15+ |
| Docker Services | 6 |
| Test Cases | 30+ |

---

## 👥 Contributors

**Muhammad Adeel Haider**  
Program: BSCYS-F24 A  
Supervisor: Sir Galib

### Acknowledgments

- Inspired by the [RedAmon](https://github.com/redamon) framework
- Built on top of industry-standard security tools (Nmap, Nuclei, Metasploit, and more)
- Leveraging modern AI capabilities with LangGraph and LangChain

---

## 🔒 Responsible Use

> **⚠️ WARNING:** This framework is designed exclusively for **authorized penetration testing**. Unauthorized use against systems you do not own or have explicit written permission to test is **illegal and unethical**. Always obtain proper authorization before testing.

---

## 🔮 Roadmap (Year 2)

| Quarter | Focus |
|---------|-------|
| Q1 (Months 13–15) | ML-based intent classification, API auth, rate limiting, audit logging |
| Q2 (Months 16–18) | Dynamic payload generation, multi-target campaigns, automated tool chaining |
| Q3 (Months 19–21) | Automated report generation, compliance mapping (PCI-DSS, HIPAA, NIST) |
| Q4 (Months 22–24) | Cloud security (AWS/Azure/GCP), container scanning, horizontal scaling |

---

*AutoPenTest-AI v1.0.0 — Year 1 Complete ✅*
