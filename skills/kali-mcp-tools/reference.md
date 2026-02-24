# Kali MCP Tools – Parameter Reference

Quick reference for tool parameters and allowed values. All tools return inner JSON: `{ "tool", "success", "message?", "data?", "error?" }`.

## Task lifecycle

| Tool | Required | Optional | Notes |
|------|----------|----------|--------|
| task_list | — | — | `data.tasks[]`: task_id, status, command, output_file, started, ended? |
| task_logs | task_id | lines (default 20) | `data.content` = output text; data.status, data.total_lines |
| task_stop | task_id | — | |

## Sessions

| Tool | Required | Optional |
|------|----------|----------|
| session_create | session_name | description, target |
| session_list | — | — |
| session_switch | session_name | — |
| session_status | — | — |
| session_delete | session_name | — |
| session_history | — | — |

## Core

| Tool | Required | Optional |
|------|----------|----------|
| run | command | — |
| fetch | url | — |
| resources | — | — |

## Scans (all return task_id; use task_logs to read output)

| Tool | Required | Optional |
|------|----------|----------|
| vulnerability_scan | target | scan_type: quick, comprehensive, web, network |
| web_enumeration | target (URL) | enumeration_type: basic, full, aggressive |
| network_discovery | target | discovery_type: quick, comprehensive, stealth |
| msf_exploit | module, rhosts | options (string) |
| nmap_nse_scan | target, scripts | ports (default "1-65535") |
| spider_website | url | depth (default 2), threads (default 10) |
| form_analysis | url | scan_type: comprehensive, quick |
| header_analysis | url | include_security (default true) |
| ssl_analysis | url | port (default 443) |
| subdomain_enum | url | enum_type: comprehensive, quick |
| web_audit | url | audit_type: comprehensive, quick |

## Evidence / files

| Tool | Required | Optional |
|------|----------|----------|
| save_output | content | filename, category (default "general") |
| create_report | title, findings | report_type: markdown, text, json |
| file_analysis | filepath | — |
| download_file | url | filename |
| exploit_search | search_term | search_type: all, web, remote, local, dos |

## run() allowlist (examples)

Allowed prefixes include: uname, whoami, ping, ifconfig, nmap, nikto, gobuster, dirb, whois, sqlmap, searchsploit, curl, wget, file, strings, ls, cat (restricted paths), head, tail, find, grep, etc. Long-running: nmap, nikto, gobuster, dirb, sqlmap, testssl.sh, amass, httpx, subfinder, gospider. Commands not matching the allowlist return `error: "command not allowed"`.
