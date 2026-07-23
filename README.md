# Automation-Script

# Network Discovery Automation Suite

A production-ready, modular network discovery and enumeration pipeline for penetration testing engagements. Built to produce structured, auditable output that integrates with CI/CD pipelines and reporting workflows.

## Features

| Feature | Description |
|---------|-------------|
| **Multi-phase discovery** | ICMP ping sweep → TCP/ARP fallback → port scanning → service enumeration |
| **Fast + deep scanning** | Masscan for speed, Nmap for depth and service detection |
| **Structured output** | JSON, Markdown, and HTML reports with engagement tracking |
| **Service categorization** | Auto-identifies web, SMB, SSH, and database services |
| **Engagement-aware** | Every scan is tagged with an engagement ID and timestamp |
| **Graceful degradation** | Missing tools or permissions don't crash the pipeline |

## Architecture
