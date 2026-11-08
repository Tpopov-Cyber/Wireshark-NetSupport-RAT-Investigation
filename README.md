# Wireshark – NetSupport RAT Investigation

## Overview

This repository contains a hands-on network forensic investigation of suspicious HTTP traffic associated with NetSupport Manager remote access software.

The investigation was conducted using Wireshark and a publicly available PCAP exercise from Malware Traffic Analysis.

The objective was to identify the affected Windows endpoint, examine potential command-and-control (C2) communications, and correlate network evidence with host and user information.

## Key Findings

- **Affected IP:** `10.2.28.88`
- **Hostname:** `DESKTOP-TEYQ2NR`
- **MAC Address:** `00:19:d1:b2:4d:ad`
- **User Account:** `brolf`
- **User Full Name:** Becka Rolf
- **External Endpoint:** `45.131.214.85:443`
- **Suspicious Activity:** Repeated HTTP POST requests with NetSupport-related headers and approximately 60-second polling intervals.

## Investigation Report

[View Case 01 – NetSupport RAT Network Traffic Investigation](case-01-netsupport-rat/README.md)

The full report includes packet-level evidence, annotated Wireshark screenshots, protocol analysis, findings, and investigative limitations.

## Tools and Techniques

Wireshark · TCP/IP · HTTP · NBNS · Kerberos · SAMR · Network Traffic Analysis · SOC Investigation

## Evidence Source

[Malware Traffic Analysis – February 28, 2026 Exercise](https://www.malware-traffic-analysis.net/2026/02/28/index.html)

This repository documents an independent educational investigation. The original PCAP is not redistributed.

---

**Analyst:** Tim Popov  
**Focus:** Junior SOC Analyst / DFIR Analyst
