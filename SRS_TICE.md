# Software Requirements Specification (SRS)
# Threat Intelligence Correlation Engine (TICE)

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) describes the functional and non-functional requirements for the Threat Intelligence Correlation Engine (TICE). The document is intended for product owners, developers, QA engineers, UI/UX designers, technical writers, and any stakeholders involved in the design, implementation, maintenance, or documentation of the platform. It captures the baseline behaviour of existing features and integrates the new **Report Export** capability.

### 1.2 Scope
TICE is a web-based application that enables security analysts to evaluate the threat posture of IPv4 addresses by aggregating intelligence from AbuseIPDB, geolocation datasets, and optional AI narrative services. The platform offers real-time health monitoring, detailed analysis, narrative reporting, and now provides export functionality for sharing findings. The system includes:
- A FastAPI backend delivering the `/api/v1/analyze` endpoint and auxiliary services.
- A React + Vite frontend that renders dashboards, accepts user input, and presents results.
- Integration with AbuseIPDB for threat intelligence and ip-api.com for geolocation data.
- Optional OpenAI-powered narrative generation.
- A new **Report Export** feature, allowing analysts to export formatted threat reports.

### 1.3 Definitions, Acronyms, and Abbreviations
- **API** – Application Programming Interface
- **AI** – Artificial Intelligence
- **Abuse Confidence Score** – A percentage representing the likelihood that an IP address is malicious based on AbuseIPDB reports.
- **CI/CD** – Continuous Integration / Continuous Deployment
- **CSV** – Comma-Separated Values
- **JSON** – JavaScript Object Notation
- **SRS** – Software Requirements Specification
- **TICE** – Threat Intelligence Correlation Engine

### 1.4 References
- AbuseIPDB API Documentation: https://docs.abuseipdb.com/
- ip-api.com Documentation: https://ip-api.com/docs
- OpenAI API Documentation: https://platform.openai.com/docs
- Project repository README.md (frontend/backend setup instructions)
- QUICKSTART.md and SETUP_INSTRUCTIONS.md within the project root

### 1.5 Overview
The remainder of this SRS describes the product environment, system features, functional flow, external interface requirements, non-functional requirements, and appendices. The **Report Export** feature is highlighted throughout the relevant sections to ensure complete integration with existing workflows.

## 2. Overall Description

### 2.1 Product Perspective
TICE is an independent web application with a service-oriented backend and a single-page application frontend. It relies on third-party RESTful APIs for threat intelligence and geolocation. The system is designed for modular expansion, enabling the integration of new data sources and features like export functionality without architectural changes.

### 2.2 Product Functions
Key functions include:
- **Health Monitoring**: Provides `/api/health` endpoint and frontend indicator showing service availability.
- **IP Analysis**: Accepts IPv4 addresses, validates input, fetches intelligence from AbuseIPDB and geolocation services, normalizes data, scores risk, and generates narratives.
- **Threat Scoring**: Applies rule-based scoring to determine risk levels (LOW, MEDIUM, HIGH, CRITICAL).
- **Narrative Generation**: Optionally uses OpenAI to produce human-readable summaries and recommended actions.
- **UI Presentation**: Displays scores, categories, triggered rules, raw data, and narratives in an interactive interface.
- **Report Export (New)**: Allows the user to export the current analysis as a downloadable file for sharing or offline archival.
- **Live Threat Feed (New)**: Persists analyses and surfaces an auto-refreshing dashboard with top risks, category distribution, and activity trends.

### 2.3 User Classes and Characteristics
- **Security Analysts**: Primary users who perform IP assessments and require exportable reports.
- **SOC Managers**: Need aggregated intelligence for operational oversight and compliance documentation.
- **Developers & QA Engineers**: Maintain and enhance the system; require detailed requirements.
- **System Administrators**: Manage deployment environments and integration keys.

### 2.4 Operating Environment
- **Backend**: Python 3.8+, FastAPI, uvicorn, running on Windows/Linux servers or containers.
- **Frontend**: React 18+, Vite build tooling, modern browsers (Chrome, Firefox, Edge, Safari).
- **External Services**: AbuseIPDB API, ip-api.com, optional OpenAI API.

### 2.5 Design and Implementation Constraints
- AbuseIPDB rate limits and plan restrictions on API calls and export usage.
- Requirement to store no persistent sensitive data; exports are generated on-demand client-side.
- Browser compatibility for download functionality (must support HTML5 downloads).
- Optional OpenAI usage must respect token and data privacy constraints.

### 2.6 Assumptions and Dependencies
- Users possess valid AbuseIPDB API keys and configure them via `.env`.
- Users have adequate network connectivity for external API calls.
- Export files are generated client-side and not stored on the server (unless future iterations dictate otherwise).
- Browser supports JavaScript ES2020 features used by the UI/export logic.

## 3. System Features

### 3.1 IP Address Analysis
**Description**: Accepts IPv4 address input, validates format, gathers data from AbuseIPDB and ip-api.com, normalizes and enriches results.
- **Priority**: High
- **Stimulus/Response**: User submits IP → System performs validation → On success returns analysis payload.
- **Functional Requirements**:
  - FR-AN-01: Validate IPv4 format before backend submission.
  - FR-AN-02: Backend shall call AbuseIPDB `/check` endpoint with `maxAgeInDays=90`.
  - FR-AN-03: Backend shall call ip-api.com for geolocation data.
  - FR-AN-04: Normalizer shall merge AbuseIPDB and geolocation data into `NormalizedThreatReport` schema.
  - FR-AN-05: On errors (validation, network, external API) system shall surface descriptive messages.

### 3.2 Threat Scoring
**Description**: Applies rule-based heuristics considering AbuseIPDB abuse confidence, reports, categories, geography, and suspicious indicators.
- **Priority**: High
- **Functional Requirements**:
  - FR-SC-01: Score shall be capped between 0 and 100.
  - FR-SC-02: Risk level shall map to inclusive ranges: LOW(0-25), MEDIUM(26-50), HIGH(51-75), CRITICAL(76-100).
  - FR-SC-03: Triggered rules shall be returned to the frontend for display.

### 3.3 Narrative Generation
**Description**: Produces plain-text threat narratives summarizing findings.
- **Priority**: Medium
- **Functional Requirements**:
  - FR-NR-01: Default narrative template shall be used if OpenAI key is absent.
  - FR-NR-02: If OpenAI key is provided, backend shall attempt to generate AI narrative with fallback on failure.

### 3.4 User Interface Presentation
**Description**: Frontend displays the analysis results, health status, error states, and interactive controls.
- **Priority**: High
- **Functional Requirements**:
  - FR-UI-01: Show abuse confidence score with color-coded styling (green/yellow/red/dark red).
  - FR-UI-02: Display triggered rules, threat categories, raw JSON data, geolocation, and narrative.
  - FR-UI-03: Provide visual indicator for backend health status.
  - FR-UI-04: Disable submission button during pending requests.

### 3.5 Report Export (New)
**Description**: Enables analysts to export the current IP analysis into a downloadable report.
- **Priority**: High (requested feature)
- **Functional Requirements**:
  - FR-RE-01: UI shall render an “Export” button adjacent to analysis results.
  - FR-RE-02: When triggered, the system shall package the current report into a downloadable file (default format CSV or JSON; see Section 4.2.2).
  - FR-RE-03: Exported artifact shall include key fields: IP address, threat score, risk level, abuse confidence, total reports, categories, triggered rules, narrative, timestamp, and geolocation details.
  - FR-RE-04: Export shall execute client-side to avoid storing sensitive data on the server.
  - FR-RE-05: If data is unavailable (e.g., analysis not yet run), the export button shall be disabled or show tooltips explaining the requirement to analyze first.
  - FR-RE-06: System shall notify users of successful or failed export attempts via on-screen messaging.

### 3.6 Live Threat Feed Dashboard (New)
**Description**: Provides a "war-room" style dashboard with a card wall, summary widgets, and activity trend charts backed by the persisted analyses.
- **Priority**: High
- **Functional Requirements**:
  - FR-LF-01: The backend shall persist every analysis (including score, categories, raw data) to a local repository (default SQLite file) within the configured retention policy.
  - FR-LF-02: The system shall expose `/api/v1/reports/recent` returning the most recent analyses with metadata (e.g., occurrence count, timestamps).
  - FR-LF-03: The system shall expose `/api/v1/reports/stats` returning aggregates (top risks, risk mix, category counts, hourly activity, overall metrics).
  - FR-LF-04: The frontend dashboard shall auto-refresh (default 15 seconds) and provide a manual refresh control.
  - FR-LF-05: Cards shall display severity colouring, "New" badge for first-time observations, and "Most Reported" badge for frequent offenders.
  - FR-LF-06: Dashboard widgets shall present top risk list, trend sparkline/heatmap, and category distribution chips.
  - FR-LF-07: Users shall be able to configure retention via environment variables (`REPORT_RETENTION_DAYS`, `REPORT_RETENTION_LIMIT`).

## 4. External Interface Requirements

### 4.1 User Interfaces
- **Input Form**: IP address field, “Analyze” button, backend health indicator.
- **Results Panel**: Displays threat score, risk level, categories, triggered rules, narrative, raw data (collapsible), geolocation details.
- **Export Control (New)**: Prominently placed “Export” button within the results panel, styled consistently with existing action buttons.
- **Live Dashboard (New)**: Dedicated route (`/dashboard`) with threat card grid, summary widgets, trend sparkline, and auto-refresh controls.
- **Error Notifications**: Banner-style warnings for invalid IP or API failures.

### 4.2 Hardware Interfaces
None. Application is client-server over standard hardware.

### 4.3 Software Interfaces
- AbuseIPDB REST API (`/api/v2/check`)
- ip-api.com (`/json/{ip}`)
- Optional OpenAI chat completions API
- Browser File API for download generation (Report Export)
- TICE REST API extensions (`/api/v1/reports/recent`, `/api/v1/reports/stats`) for dashboard data

### 4.4 Communications Interfaces
- HTTPS for external API calls
- HTTP/HTTPS between frontend and backend (default `http://localhost:3000` ↔ `http://localhost:8000`)
- CORS configured to allow frontend origins

### 4.5 Export Format Specification
- **Default Format**: JSON file named `tice-report-{timestamp}.json`
- **Optional Format**: CSV export (future iteration; backlog item)
- **Content Requirements**:
  - Metadata: generation timestamp, application version (if available)
  - Analysis Data: IP, threat score, risk level, abuse confidence score, total reports, number of distinct reporters, ISP, domain, geolocation, triggered rules, categories, narrative, raw AbuseIPDB response snippet
- **Validation**: Ensure proper JSON encoding; if CSV option is implemented, escape commas and line breaks.

### 4.6 Persistence Specification (New)
- **Storage Backend**: SQLite file by default (`REPORT_DB_PATH`), with optional JSON/datastore swap.
- **Retention**: Configurable via `REPORT_RETENTION_DAYS` (age-based) and `REPORT_RETENTION_LIMIT` (count-based).
- **Schema**: Stores IP, timestamps, score, risk level, abuse confidence, report counts, categories, triggered rules, narrative, country, ASN, raw payload.
- **Accessibility**: Repository must be readable by analysis API and dashboard endpoints; no direct filesystem exposure.

## 5. Other Non-Functional Requirements

### 5.1 Performance Requirements
- Backend analysis response time should average < 3 seconds assuming AbuseIPDB responds within SLA.
- Export operation should complete in < 1 second for standard report sizes (limited data volume).
- Dashboard API calls (`/reports/recent`, `/reports/stats`) should respond in < 500 ms for the default retention window.

### 5.2 Safety Requirements
- Sensitive API keys must not be exposed in exports or logs.
- Stored reports contain operational data; database files should inherit filesystem permissions from the host environment.
- No persistence of generated exports on the server.

### 5.3 Security Requirements
- API keys stored in `.env` and not committed to source control.
- Export should not contain user authentication tokens or secrets.
- CORS settings to limit origins in production deployments.

### 5.4 Software Quality Attributes
- **Reliability**: Graceful error handling, retry logic for AbuseIPDB requests, periodic persistence cleanup.
- **Usability**: Clear UI indicators, disabled buttons when actions unavailable, confirmation messages for export, auto-refresh status indicator on dashboard.
- **Maintainability**: Modular services, separated normalization/scoring layers, repository abstraction for storage, readable SRS.
- **Portability**: Runs on modern web browsers; backend deployable on Windows/Linux hosts.

### 5.5 Business Rules
- Export feature shall require a completed analysis in the current session.
- AbuseIPDB usage must adhere to rate limits; consider caching results or notifying users if limits are reached.
- Dashboard auto-refresh interval defaults to 15 seconds and should not be set below 5 seconds to avoid API throttling.

## 6. Appendix

### 6.1 Future Enhancements
- Support for multiple export formats (PDF, CSV) and scheduling recurring exports.
- Multi-IP batch analysis and bulk exports.
- Role-based access controls limiting export functionality.
- Integration with ticketing systems (e.g., Jira, ServiceNow) to attach exported reports automatically.

### 6.2 Traceability Matrix (Excerpt)
| Requirement ID | Description | Source |
| --- | --- | --- |
| FR-AN-01 | Validate IPv4 format client-side | Existing functionality |
| FR-AN-02 | Query AbuseIPDB `/check` endpoint | Existing functionality |
| FR-RE-01 | Provide Export button in UI | New feature request |
| FR-RE-03 | Export includes key analysis fields | New feature request |
| FR-RE-06 | Export success/failure notification | New feature request |
| FR-LF-02 | Dashboard recent reports API | Live feed enhancement |
| FR-LF-06 | Dashboard widgets show trends/categories | Live feed enhancement |

---
This SRS reflects the baseline system augmented with the **Report Export** feature. All stakeholders should review the requirements before implementation to ensure alignment with security, usability, and compliance objectives.
