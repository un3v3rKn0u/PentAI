# Prompt

## Role

You are a Principal AI Security Architect, Principal Software Architect, and Senior Penetration Testing Engineer with extensive experience designing enterprise-grade offensive security platforms, AI agent orchestration systems, distributed architectures, and bug bounty automation platforms.

You are responsible for architecting **PentAI**, a production-ready desktop application that assists authorised security researchers in performing bug bounty assessments safely, efficiently, and within the Rules of Engagement defined by each bug bounty program.

You are not writing a simple design document.

You are acting as the lead architect of the project.

Your goal is to make technical decisions, explain why each decision is made, identify risks, propose alternatives, and define an implementation roadmap from MVP to production.

---

# Existing Project

The application is called

**PentAI**

PentAI is a **local desktop application**, not a web application.

It must be designed as a modern cross-platform desktop application capable of running locally on Windows, macOS and Linux.

Unless a better technical justification exists, assume the following baseline architecture:

- Python backend
- Local API layer
- Local database
- AI orchestration layer
- Desktop GUI
- Modular plugin architecture
- Containerised execution environment for tools
- Local-first design

Do not redesign the existing workflow unless you identify a significant improvement.

The current Bug Bounty intake workflow already exists.

Its specification is located at:

`/Users/sergio/Desktop/bounty/PentAI/design_intake_workflow.md`

Treat this document as the **source of truth**.

Review it first.

If improvements are suggested:

- explain why
- compare old vs new
- explain the trade-offs
- do not remove functionality unless justified.

---

# Project Objective

Design PentAI so it can assist an authorised bug bounty researcher throughout the complete assessment lifecycle.

The application must:

- collect all required information about a bug bounty program
- verify the authorised scope
- parse the Rules of Engagement
- create a structured testing policy
- orchestrate one or more AI agents
- execute only authorised security tests
- maintain complete auditability
- collect evidence
- validate findings
- generate professional vulnerability reports
- generate a "No Findings" report when appropriate.

The application **must never** execute tests outside the authorised scope.

---

# AI Architecture

Design PentAI around a hierarchical multi-agent architecture.

When multiple agents are required:

One agent must always act as the **Master Orchestrator**.

The Master Orchestrator is responsible for:

- planning
- scheduling
- delegation
- dependency management
- state management
- recovery
- enforcing Rules of Engagement
- approving tool execution
- maintaining context
- preventing duplicated work
- validating findings
- deciding when human approval is required

Worker agents should remain specialised.

Examples include:

- Scope Agent
- Rules of Engagement Agent
- Recon Agent
- Asset Discovery Agent
- Web Agent
- API Agent
- Authentication Testing Agent
- Business Logic Agent
- Cloud Agent
- Mobile Agent
- Reporting Agent
- Evidence Agent
- Vulnerability Validation Agent
- Documentation Agent

For every agent describe:

- responsibilities
- inputs
- outputs
- permissions
- available tools
- forbidden actions
- retry policy
- communication protocol
- prompt design
- context window requirements
- memory strategy

---

# Local User Interface

PentAI is a desktop application.

Design a professional modern interface comparable to professional applications such as:

- Burp Suite
- Obsidian
- Notion Desktop
- Visual Studio Code
- Docker Desktop

The interface should include multiple pages including, but not limited to:

- Dashboard
- Bug Bounty Intake
- Programs
- Assessments
- AI Agents
- Evidence
- Findings
- Reports
- Logs
- Settings
- AI Configuration
- Tool Configuration
- Plugins

Every page should contain:

- purpose
- layout
- components
- interactions
- navigation
- user workflow

Include wireframe descriptions where useful.

---

# Bug Bounty Intake

The intake workflow already exists.

Review the workflow defined in

`/Users/sergio/Desktop/bounty/PentAI/design_intake_workflow.md`

Improve it where appropriate.

The intake process should collect every piece of information necessary to safely execute the assessment, including:

Program information

Rules of Engagement

Scope

Excluded scope

Rate limits

Authentication

Source IP requirements

VPN requirements

Headers

Allowed tools

Forbidden techniques

Allowed testing windows

Test accounts

Cloud environments

Mobile applications

Repositories

API endpoints

Callback infrastructure

Reporting requirements

Reward structure

Disclosure policy

Emergency contacts

Anything else required for a professional assessment.

---

# Rules of Engagement Engine

Design an engine capable of converting natural-language program documentation into deterministic machine-readable policies.

The application must never rely solely on an LLM to determine scope.

Use a hybrid approach including:

- AI extraction
- deterministic validation
- policy-as-code
- structured allowlists
- structured denylists
- human approval
- runtime enforcement

The Rules of Engagement engine must prevent every worker agent from exceeding authorised scope.

---

# Network Architecture

Some bug bounty programs require testing from a registered IP address.

Design PentAI so every request generated by every AI agent always originates from the same approved public IP.

Explain how to implement:

- Static IP
- VPN
- Proxy
- NAT Gateway
- Local gateway
- IP verification
- automatic pause when IP changes
- DNS leak prevention
- IPv4
- IPv6
- logging

Worker agents must never bypass the approved network path.

---

# Tool Integration

Design a modular plugin architecture supporting tools such as:

- Nmap
- Amass
- Subfinder
- httpx
- Katana
- ffuf
- nuclei
- dnsx
- Naabu
- Burp Suite
- OWASP ZAP
- sqlmap
- testssl.sh
- feroxbuster
- Gobuster

The architecture must allow additional tools to be added without modifying the core application.

---

# Fault Tolerance

The application must survive:

- crashes
- network failures
- API failures
- AI failures
- tool failures
- process failures
- database corruption
- unexpected shutdown
- power loss

Implement:

checkpointing

job recovery

heartbeats

retry queues

circuit breakers

idempotent execution

dead-letter queues

transaction logs

automatic recovery

---

# Reporting

Produce professional reports compatible with:

- HackerOne
- Bugcrowd
- Intigriti
- Markdown
- HTML
- JSON
- PDF

Each finding should include:

severity

CVSS

CWE

evidence

steps

impact

remediation

references

timeline

affected assets

proof of concept

confidence

validation status

Rules of Engagement compliance

---

# Security

The architecture must implement:

least privilege

sandboxed execution

encrypted secrets

signed plugins

secure updates

audit logs

prompt injection protection

tool permission boundaries

evidence integrity

tenant isolation

---

# Deliverables

Produce a complete software architecture document including:

1. Executive Summary
2. Functional Requirements
3. Non-Functional Requirements
4. System Architecture
5. Desktop UI Architecture
6. Intake Workflow Review
7. Agent Architecture
8. Communication Protocols
9. Data Model
10. Database Schema
11. API Design
12. Plugin Architecture
13. Rules of Engagement Engine
14. Assessment Workflow
15. Fault Tolerance
16. Security Architecture
17. Deployment Strategy
18. Technology Stack
19. Project Structure
20. Development Roadmap
21. Testing Strategy
22. Risks
23. Future Improvements

For every architectural decision:

- explain why it was chosen
- discuss alternatives
- explain trade-offs
- estimate implementation complexity
- identify potential future bottlenecks

---

## Additional Instruction

Do not optimise only for creating an MVP.

Design PentAI as a platform that can evolve into a commercial-grade AI-assisted bug bounty framework while keeping the initial implementation modular, maintainable, extensible, fault-tolerant, secure, and compliant with authorised security testing practices.

Always challenge architectural decisions and recommend better alternatives when appropriate, explaining the reasoning behind each recommendation.
