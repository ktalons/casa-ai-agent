# Capstone AI Agent

AI-Assisted Cybersecurity Analysis Agent - A modular AI agent supporting log and network traffic analysis for SME/MSP security operations. Guides investigative workflows with explainable reasoning aligned to NIST standards.

## Overview

Security analysts in small-to-medium enterprise (SME) and managed service provider (MSP) environments face constant challenges analyzing large volumes of logs and network telemetry. This project proposes an AI-assisted agent that supports analysis tasks while maintaining human-in-the-loop decision-making.

Rather than fully autonomous threat detection, the agent guides investigative workflows, suggests appropriate tools and steps, and explains its reasoning aligned with established cybersecurity standards.

## Architecture

The system is built on [Daniel Miessler's Personal AI Infrastructure](https://github.com/danielmiessler/Personal_AI_Infrastructure) framework, implementing the following core modules:

| Module | Description |
|--------|-------------|
| **Overseer/Core** | Routes analyst queries to appropriate agents |
| **Log Analysis Agent** | Guides log investigation using NIST SP 800-92 principles |
| **Network Traffic Analysis Agent** | Assists with PCAP and flow analysis |
| **Purple-Team Mapping** | Translates findings into detection opportunities aligned with NIST CSF 2.0 |
| **Explainability Module** | Provides step-by-step reasoning traces for all recommendations |

## Standards Alignment

- **NIST SP 800-92** - Guide to Computer Security Log Management
- **NIST SP 800-61** - Computer Security Incident Handling Guide
- **NIST CSF 2.0** - Cybersecurity Framework for detection and response
- **NIST AI RMF** - AI Risk Management Framework for transparency

## Tech Stack

- Python (primary)
- TypeScript / Bun (PAI framework)
- Claude (LLM backbone)

## Status

Senior Capstone Project - In Development

## License

MIT
