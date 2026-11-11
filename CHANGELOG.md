# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Live demo on GitHub Pages. It serves only the frontend, so it runs in checklist-only mode with progress saved in the browser, shows a banner that explains this, does not look for a backend, and follows the browser language when none is chosen.

## [1.0.0] - 2026-11-11

First tagged release. It covers the work from August to November 2026.

### Testing workflow

- WSTG v4.2 checklist with a list and detail layout, test steps, example commands, tools and a three-state result (no issue, issue found, not applicable), in English and Turkish.
- OWASP Top 10:2025 and OWASP Top 10 for LLM Applications 2025 checklists.
- Project-based flow with five steps, a "next step" card, page help and empty states.
- Scope definition, Attack Surface Discovery and a read-only attack surface workspace.
- Authorization matrix of roles and endpoints, which creates an ATHZ finding when the results don't match.
- Notebook, WSTG to OWASP Top 10 and CWE mapping, and study metrics.
- Kanban board.

### Findings and evidence

- CVSS v3.1 calculator and severity-sorted findings with filters.
- Finding templates, a proof-of-concept field and duplicate detection.
- Evidence uploads with paste and drag and drop, and content validation.
- Import from Nmap, Nikto, WPScan, Burp Suite and ZAP.
- Rule-based attack-chain correlation.
- Retest workflow and retest report.

### Reports

- DOCX, HTML and PDF reports with an executive summary, risk summary, findings and an authorization testing section.
- Report percentages and dates follow the report language, and coverage is counted against the full checklist.

### AI assistance (optional)

- Anthropic, OpenAI, Google Gemini and Ollama, with keys entered in the interface (bring your own key) and stored encrypted.
- Drafts for descriptions, remediation and summaries, CWE, severity and CVSS suggestions, next-test suggestions and screenshot analysis. Every AI output is a draft for the user to review.
- Secret and personal data redaction before data is sent to a provider.

### Security

- Local-only defaults: the API binds to `127.0.0.1`, debug is off, CORS is narrow, Origin and Host are checked, and a random secret key is generated.
- Single-user password sign-in with a `SameSite=Strict` session cookie, login throttling and a loopback-only first-password screen.
- Internal error details are hidden from responses and shown only in the backend log under an error ID.

### Setup and project

- Docker image and Docker Compose setup, published on `127.0.0.1` only.
- Project backup to a single JSON file and restore as a new project.
- Tests for the backend and frontend, run in CI on every pull request.
- Licensing clarified: code under MIT, `data/` under CC BY-SA 4.0, and the project is independent from OWASP.
- README in English and Turkish, with a demo GIF and screenshots; contributing guide, security policy and issue templates.

[Unreleased]: https://github.com/enesbaldemir/WSTG-Copilot/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/enesbaldemir/WSTG-Copilot/releases/tag/v1.0.0
