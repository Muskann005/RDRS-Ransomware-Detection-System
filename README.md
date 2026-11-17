# RDRS – Ransomware Detection and Response System

## 1. Project Overview

RDRS (Ransomware Detection and Response System) is a Python-based cybersecurity application designed to monitor file-system activity, detect suspicious behavior, identify potential ransomware activity, and support incident response.

The system combines real-time file monitoring, entropy analysis, process monitoring, threat scoring, incident management, database storage, REST API services, and a web-based dashboard.

The project is developed as a cybersecurity internship project using Python and Docker.

## 2. Project Objectives

- Monitor file-system activity in real time.
- Detect suspicious file modifications.
- Identify files with unusually high entropy.
- Monitor running processes for suspicious activity.
- Evaluate suspicious events using a detection engine.
- Calculate threat scores.
- Record security events and incidents.
- Support quarantine-based incident response.
- Provide a dashboard for security monitoring.
- Generate incident reports in JSON and CSV formats.

## 3. Key Features

### 3.1 Real-Time File Monitoring

- Monitors configured directories.
- Detects file-system activity.
- Tracks suspicious file modifications.
- Records file activity for further investigation.

### 3.2 Entropy-Based Detection

- Calculates file entropy.
- Identifies unusually high-entropy files.
- Uses entropy analysis as an indicator of possible encryption activity.
- Helps identify potentially suspicious file changes.

### 3.3 Process Monitoring

- Collects information about running processes.
- Supports identification of unknown or suspicious processes.
- Provides process information to the monitoring and detection workflow.

### 3.4 Detection Engine

- Evaluates monitored events.
- Analyzes suspicious file activity.
- Uses detection information to identify potential threats.
- Supports the threat assessment workflow.

### 3.5 Threat Scoring

- Assigns threat scores to suspicious activity.
- Helps classify potential security incidents.
- Supports prioritization of detected threats.

### 3.6 Incident Response

- Records detected incidents.
- Supports quarantine operations.
- Preserves evidence for investigation.
- Supports safe testing through simulation mode.

### 3.7 Database Management

- Uses SQLite for persistent data storage.
- Stores security events and process information.
- Supports incident and report retrieval.
- Uses SQLAlchemy for database interaction.

### 3.8 REST API

- Provides system status information.
- Exposes monitoring and detection endpoints.
- Supports settings management.
- Provides access to events, alerts, and reports.

### 3.9 Web Dashboard

The dashboard provides a centralized interface for monitoring RDRS.

Dashboard features include:

- Threat level and threat score.
- CPU and process information.
- File activity information.
- Security alerts.
- Incident information.
- Reports.
- Charts and monitoring statistics.
- Settings management.
- Automatic dashboard refresh.

### 3.10 Reporting

- Generates incident reports in JSON format.
- Supports CSV incident exports.
- Provides aggregate report generation.
- Allows report retrieval through API endpoints.

## 4. System Architecture

RDRS follows a modular architecture.

### Main Workflow

1. File monitoring collects file-system activity.
2. Entropy detection analyzes suspicious file content.
3. Process monitoring collects running-process information.
4. The detection engine evaluates collected activity.
5. Threat scoring assesses the severity of suspicious events.
6. Incident response handles detected incidents.
7. The database stores security events and incident information.
8. FastAPI exposes monitoring and reporting functionality.
9. The dashboard presents monitoring results.

### Architecture Components

| Component | Responsibility |
|---|---|
| File Monitoring | Monitors file-system activity |
| Entropy Detector | Analyzes file entropy |
| Process Monitor | Collects process information |
| Detection Engine | Evaluates suspicious activity |
| Threat Scoring | Assesses threat severity |
| Incident Response | Supports incident handling |
| Database | Stores events and records |
| FastAPI | Provides REST API services |
| Dashboard | Displays monitoring information |
| Reporting | Generates incident reports |

## 5. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application development |
| FastAPI | REST API development |
| SQLite | Database storage |
| SQLAlchemy | Database interaction |
| Docker | Application containerization |
| Docker Compose | Container management |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard interactions |
| Pytest | Automated testing |
| pytest-cov | Code coverage measurement |

## 6. Project Structure

The following is a high-level representation of the project structure. Individual files and subdirectories may vary according to the implementation.

```text
rdrs/
│
├── config/
│
├── data/
│
├── logs/
│
├── reports/
│
├── src/
│   ├── api/
│   │
│   ├── database/
│   │
│   ├── detection/
│   │
│   ├── monitoring/
│   │
│   ├── response/
│   │
│   ├── entropy_detector.py
│   ├── process_monitor.py
│   ├── detection_engine.py
│   ├── threat_scoring.py
│   └── incident_response.py
│
├── tests/
│
├── .dockerignore
├── config.yaml
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── LICENSE
└── README.md
```

## 7. Installation and Setup

### Prerequisites

- Windows 11, Linux, or macOS.
- Python 3.10 or later.
- Docker Desktop for Docker deployment.
- Git (optional).

### Step 1: Create a Virtual Environment

```bash
python -m venv .venv
```

### Step 2: Activate the Virtual Environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## 8. Running the Application Locally

Start the FastAPI application:

```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

After starting the application, open the following URLs:

- Dashboard: http://localhost:8000/dashboard
- API Documentation: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

## 9. Docker Deployment

RDRS supports containerized deployment using Docker and Docker Compose.

### Step 1: Build and Start the Application

```bash
docker compose up -d --build
```

### Step 2: Check Container Status

```bash
docker compose ps
```

### Step 3: View Application Logs

```bash
docker compose logs -f rdrs
```

### Step 4: Check Application Health

```bash
Invoke-RestMethod http://localhost:8000/health
```

### Step 5: Stop the Application

```bash
docker compose stop
```

### Step 6: Restart the Application

```bash
docker compose restart rdrs
```

## 10. Persistent Data Storage

Docker Compose mounts project directories into the container.

| Host Directory | Container Directory | Purpose |
|---|---|---|
| config.yaml | /app/config.yaml | Application configuration |
| reports/ | /app/reports/ | Generated reports |
| logs/ | /app/logs/ | Application logs |
| data/ | /app/data/ | Application data |
| config/ | /app/config/ | Configuration directory |

These mounts allow application data to remain available on the host when the container is recreated.

Avoid Docker commands that remove persistent volumes or project data.

## 11. REST API Endpoints

The following endpoints are implemented in the FastAPI application.

| HTTP Method | Endpoint | Description |
|---|---|---|
| GET | / | Root endpoint |
| GET | /health | Application and database health |
| GET | /status | System status |
| GET | /processes | Process information |
| POST | /scan | Submit data for scanning |
| GET | /events | Retrieve security events |
| GET | /alerts | Retrieve alerts |
| GET | /reports | Retrieve reports |
| GET | /reports/incidents/{incident_id} | Retrieve an incident report |
| GET | /reports/incidents/{incident_id}/csv | Export an incident as CSV |
| GET | /reports/csv | Export aggregate reports as CSV |
| GET | /settings | Retrieve application settings |
| POST | /settings | Update application settings |
| GET | /monitoring/status | Monitoring status |
| GET | /detection/status | Detection status |

### API Documentation

FastAPI provides interactive API documentation.

Open:

http://localhost:8000/docs

## 12. Dashboard

The RDRS dashboard provides a centralized view of system monitoring and security activity.

The dashboard includes:

- Current threat level.
- Threat score.
- CPU and process information.
- File activity.
- Security alerts.
- Incident information.
- Reports and charts.
- Application settings.
- Automatic refresh.

Dashboard URL:

http://localhost:8000/dashboard

## 13. Database

RDRS uses SQLite for persistent storage.

SQLAlchemy is used for database interaction.

The database supports storing and retrieving information related to:

- Security events.
- Process information.
- Incident records.
- Detection activity.
- Monitoring information.

The database is initialized by the application during startup.

## 14. Testing and Code Coverage

The project uses Pytest for automated testing.

### Run All Tests

```bash
python -m pytest
```

### Run Tests with Coverage

```bash
python -m pytest --cov=src --cov-report=term-missing
```

### Latest Verified Test Results

| Metric | Result |
|---|---:|
| Total tests passed | 108 |
| Failed tests | 0 |
| Overall code coverage | 90% |
| RDRS controller coverage | 94% |

These results represent the latest recorded test run. Results may change if the source code or tests are modified.

## 15. Safety and Security Considerations

- Use authorized test environments only.
- Do not execute real malware on a personal computer.
- Use controlled test files and simulations.
- Keep simulation mode enabled during safe testing.
- Preserve original files and investigation evidence.
- Test quarantine and response operations in an isolated environment.
- Do not disable security controls to run tests.

RDRS is a defensive cybersecurity project intended for authorized monitoring, detection, and testing.

## 16. Current Project Status

The following development areas have been implemented and tested:

- Environment and project setup.
- Entropy detection.
- Real-time file monitoring.
- Database integration.
- Process monitoring.
- Detection engine.
- Threat scoring.
- Incident response.
- REST API.
- Web dashboard.
- JSON and CSV reporting.
- Automated testing.

Docker deployment and documentation are part of the final deployment and documentation phase.

## 17. Future Enhancements

Possible future improvements include:

- Email and desktop security notifications.
- Advanced behavioral detection.
- Improved process anomaly detection.
- More detailed incident analytics.
- Role-based dashboard access.
- Additional automated response options.
- Improved detection evaluation using larger datasets.

These are proposed enhancements and are not claimed as completed features.

## 18. License

This project is distributed under the MIT License.

See the LICENSE file for the complete license text.

## 19. Project Information

**Project Name:** Ransomware Detection and Response System (RDRS)

**Project Type:** Cybersecurity Internship Project

**Primary Programming Language:** Python

**Backend Framework:** FastAPI

**Database:** SQLite

**Deployment:** Docker and Docker Compose

**Testing Framework:** Pytest

---

RDRS – Ransomware Detection and Response System
