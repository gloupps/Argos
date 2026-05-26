# 🧠 CTI Automation Platform

A modular automation platform designed to streamline **Cyber Threat Intelligence (CTI)** workflows by integrating **OpenCTI**, **SIEM data**, and external enrichment sources.

This tool provides a unified interface to:
- Automate report processing
- Investigate indicators in SIEM
- Qualify and prioritize IOCs
- Manage threat intelligence knowledge

---

## 🚀 Overview

The platform is built around 4 main modules (as seen in the UI):

1. 📄 Report Automation  
2. 🔎 SIEM Investigation  
3. 🧪 IOC Qualification  
4. 📚 Knowledge Management  

Each module automates a specific part of the CTI lifecycle.

---

# 📄 1. Report Automation

## 🎯 Purpose
Automate actions on existing OpenCTI reports or create new ones from raw IOC data.

## ⚙️ Features

### 🔹 Create Indicators
- Extract observables from a report
- Automatically generate **Indicators**
- Link indicators to observables

### 🔹 Create Relations
- Build relationships between:
  - Indicators
  - Observables
  - Reports
- Ensures graph consistency in OpenCTI

### 🔹 Enable / Disable Detection
- Tag indicators for detection pipelines
- Typically used to integrate with SIEM or EDR rules

### 🔹 Enrich Report
- Add:
  - Labels
  - External references
  - Additional context

### 🔹 Create Report from IOC List
- Input: raw IOC list (IPs, domains, hashes…)
- Output:
  - New OpenCTI report
  - Observables + Indicators automatically created

---

# 🔎 2. SIEM Investigation

## 🎯 Purpose
Search for IOC activity in SIEM and act on results.

## ⚙️ Features

### 🔹 Investigation Modes
- From an OpenCTI report
- From manual IOC input

### 🔹 Query Parameters
- Indicators / IOCs
- Time range (last X days)

### 🔹 Results
Displays:
- IOC
- Number of hits
- Last seen timestamp
- Source (log, host, interface…)

---

## ⚡ Actions on Results

### Report Mode
- Add to detection
- Create note in OpenCTI
- Create sightings

### Manual Mode
- Add IOC to report
- Create report
- Create sightings
- Add to detection

---

## 🧠 Behind the scenes

- Queries SIEM (e.g. QRadar)
- Parses results
- Maps data into:
  - Sightings
  - Notes
  - Indicators enrichment

---

# 🧪 3. IOC Qualification

## 🎯 Purpose
Assess IOC relevance by correlating multiple data sources.

## ⚙️ Features

### 🔹 Multi-source Analysis
Each IOC is evaluated against:
- OpenCTI (existing knowledge)
- SIEM (activity)
- VirusTotal (reputation)

### 🔹 Output Table
| IOC | OpenCTI | SIEM | VT |
|-----|--------|------|----|

---

## ⚡ Actions

### Report Mode
- Add to detection
- Create SIEM note
- Create sightings
- Enrich report

### Manual Mode
- Add IOC to report
- Create report
- Create sightings
- Add to detection

---

## 🧠 Logic

This module acts as a **decision engine**:
- Helps analysts prioritize IOCs
- Automates enrichment and classification

---

# 📚 4. Knowledge Management

## 🎯 Purpose
Continuously feed and maintain CTI knowledge.

---

### 🔹 VirusTotal IOC Stream
- Fetch latest IOCs from VirusTotal
- Automatically generate a report in OpenCTI

---

### 🔹 Generate Sightings from Offense
- Input: SIEM Offense ID
- Output:
  - Extract observables
  - Create sightings
  - Link to indicators

---

# 🔧 How the Code Works

## 📋 Overall Flow

```
User Action (UI)
    ↓
API Endpoint (/api/run)
    ↓
AutomationService.start_job()
    ↓
JobManager (creates job ID)
    ↓
SocketIO Background Task
    ↓
Async Job Execution (_run_job)
    ↓
Integration Clients (OpenCTI, QRadar, VT)
    ↓
Job Completion → Frontend Update (WebSocket)
```

## 🏛️ Core Components

### 1. **Entry Point** (`main.py`)
- Initializes the Flask application
- Sets up SocketIO for real-time communication
- Runs the webserver on `127.0.0.1:5555`

```python
from app import OpenCTIAutomationApp
app_instance = OpenCTIAutomationApp()
app = app_instance.app
socketio = app_instance.socketio
```

### 2. **Application Bootstrap** (`app/__init__.py`)
- **OpenCTIAutomationApp** class initializes all components:
  - Flask webserver (frontend → backend)
  - SocketIO (backend → frontend, real-time updates)
  - Configuration loader
  - Job manager
  - Integration clients (OpenCTI, QRadar, VirusTotal)
  - Automation service

### 3. **HTTP Routes** (`app/services/automation_routes.py`)
Defines Flask endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Renders the UI (index.html) |
| `/api/run` | POST | Starts a new automation job |
| `/api/job/<job_id>` | GET | Retrieves job status/results |
| `/test-ws` | GET | Tests WebSocket connection |

**Example request:**
```json
POST /api/run
{
  "action": "create_indicators",
  "report_id": "report--xxx",
  "params": { ... }
}
```

### 4. **Job Management** (`app/services/job_manager.py`)
Manages asynchronous task execution:
- Creates unique job IDs
- Tracks job status (running, completed, failed)
- Stores job results
- Emits updates to frontend via WebSocket

**Job Lifecycle:**
```
create_job() → running → complete_job() → completed
                      ↓
                   fail_job() → failed
```

### 5. **Automation Service** (`app/services/automation_service.py`)
Core business logic orchestrator:
- Routes actions to appropriate handlers
- Runs jobs asynchronously
- Manages concurrent operations
- Handles errors and emits status updates

**Key Methods:**
- `start_job(data)` - Triggers a new job
- `_run_async_job(job_id, data)` - Executes job in background
- `_run_job(job_id, data)` - Main router (implements each action)

### 6. **Integration Clients**

#### 📡 **OpenCTI Client** (`app/integrations/opencti_client.py`)
Communicates with OpenCTI GraphQL API:
- Creates/updates indicators, observables, reports
- Manages relationships and sightings
- Executes GraphQL queries from `app/utils/opencti_queries.py`
- Handles batch operations with async concurrency

**Example:**
```python
await self.opencti.create_indicator(
    value="malware-indicator",
    pattern="[file:hashes.MD5 = 'hash']",
    labels=["malware"]
)
```

#### 🔍 **QRadar AQL Client** (`app/integrations/qradar_aql_client.py`)
Queries SIEM for IOC activity:
- Executes AQL (Ariel Query Language) searches
- Parses results
- Detects indicator types
- Returns formatted hit counts and timestamps

#### 🦠 **VirusTotal Client** (`app/integrations/vt_client.py`)
Enriches IOCs with reputation data:
- Looks up file hashes, IPs, domains
- Returns threat scores
- Fetches associated context

### 7. **Configuration** (`app/core/config.py`)
Loads settings from `config.yaml`:
```yaml
opencti:
  url: "http://localhost:8000"
  token: "your_token"
  
qradar:
  url: "https://your-qradar"
  token: "your_token"
  
virustotal:
  token: "your_token"

shodan:
  token: "your_token"
```