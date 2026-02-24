---
name: kali-mcp-tools
description: Teaches how to use the Kali MCP server tools for penetration testing and security scans. Covers response format (inner JSON), task lifecycle (task_list, task_logs, task_stop), sessions, run vs scan tools, and when to use each. Use when assisting with this MCP server, pentesting workflows, or when the user asks how to use Kali tools or scan targets.
---

# Kali MCP Server – Tool Usage

## Response format (inner JSON)

Every tool returns a **JSON string** with the same shape. Parse it and branch on `success`:

```json
{
  "tool": "tool_name",
  "success": true,
  "message": "optional",
  "data": { ... },
  "error": "optional"
}
```

- **Success:** `success === true`, payload in `data`, optional `message`.
- **Failure:** `success === false`, reason in `error`; `data` may still contain context (e.g. `task_id`, `output_file`).

Always parse the tool result as JSON and check `success` before using `data`.

---

## Task lifecycle (background commands and scans)

Many operations run in the **background** and write output to a file. You get a `task_id` and must use **task_logs** to read results.

| Step | Tool | When |
|------|------|------|
| Start | `run`, `vulnerability_scan`, `web_enumeration`, `network_discovery`, `msf_exploit`, `nmap_nse_scan`, `spider_website`, `form_analysis`, `header_analysis`, `ssl_analysis`, `subdomain_enum`, `web_audit` | Starts a command or scan |
| List | `task_list` | See all tasks; response `data.tasks[]` has `task_id`, `status`, `command`, `output_file` |
| Read output | `task_logs(task_id, lines?)` | Get `data.content` (and `data.status`, `data.total_lines`) |
| Stop | `task_stop(task_id)` | Stop a running task |

Rule: **Do not use `download_file` to read scan or command output.** `download_file` is for fetching from the **internet** (URLs). Server-side log/scan output is read only via **task_logs(task_id)** or **run** (e.g. `run("cat /path/to/file")`).

---

## Sessions (organize by engagement)

Sessions scope where outputs and evidence go. The **active session** is the one that receives new scan outputs and saved files.

| Tool | Purpose |
|------|--------|
| `session_create(session_name, description?, target?)` | Create session and set it active. Outputs go to this session's directory. |
| `session_list()` | List all sessions; `data.sessions[]`, `data.active_session`. |
| `session_switch(session_name)` | Set active session (e.g. switch client/engagement). |
| `session_status()` | Active session metadata: description, target, file count, recent activity. |
| `session_history()` | Action history for the active session. |
| `session_delete(session_name)` | Remove session and its data. Switch away first if it is active. |

Workflow: `session_create("Client_Alpha", target="192.168.1.0/24")` → run scans → outputs land in that session's folder. Use `session_switch` when changing engagement.

---

## Core tools

| Tool | Behavior | Returns (data / error) |
|------|----------|------------------------|
| **run**(command) | Run shell command. If allowlist marks it long-running (nmap, nikto, etc.), runs in background. | Sync: `data.stdout`, `data.stderr`, `data.command`. Background: `data.task_id`, `data.command`. Error: `error`, optional `data.command`. |
| **fetch**(url) | GET URL, return body. | `data.url`, `data.status_code`, `data.content`. Errors: `error`. |
| **resources**() | List system info and example commands. | `data.system_info`, `data.resources` (categories and commands). |

Commands are allowlist-checked; disallowed commands return `success: false` and `error: "command not allowed"`.

---

## Scan / background tools

All of these **start** a job and return `data.task_id` (and often `data.output_file`). Use **task_logs(task_id)** to read output.

- **vulnerability_scan**(target, scan_type?) — scan_type: quick, comprehensive, web, network  
- **web_enumeration**(target, enumeration_type?) — target URL; enumeration_type: basic, full, aggressive  
- **network_discovery**(target, discovery_type?) — target host or CIDR; discovery_type: quick, comprehensive, stealth  
- **msf_exploit**(module, rhosts, options?) — e.g. module `exploit/windows/smb/ms17_010_eternalblue`  
- **nmap_nse_scan**(target, scripts, ports?) — scripts e.g. `vuln`, `http-enum`  
- **spider_website**(url, depth?, threads?)  
- **form_analysis**(url, scan_type?)  
- **header_analysis**(url, include_security?)  
- **ssl_analysis**(url, port?)  
- **subdomain_enum**(url, enum_type?)  
- **web_audit**(url, audit_type?)  

---

## Evidence and files

| Tool | Use |
|------|-----|
| **save_output**(content, filename?, category?) | Save text to a timestamped file in the active session. |
| **create_report**(title, findings, report_type?) | report_type: markdown, text, json. |
| **file_analysis**(filepath) | Run file/strings/hash on a path (e.g. file from download or session). |
| **download_file**(url, filename?) | Fetch from **internet** into container. For server-side files use **task_logs** or **run("cat ...")**. |

---

## Sync vs background

- **Sync (immediate result in same call):** `fetch`, `resources`, `exploit_search`, `session_*`, `task_list`, `task_stop`, `task_logs`, `save_output`, `create_report`, `file_analysis`, `download_file`.  
- **Background (return task_id, read later):** `run` (when command is long-running), all scan tools above.

If a tool returns `data.task_id`, the next step is **task_logs(task_id)** (optionally with `lines` for tail length).

---

## Workflows

**Run a scan and get results**

1. (Optional) `session_create("Engagement", target="...")`.  
2. Call scan tool, e.g. `vulnerability_scan("192.168.1.1", "quick")`.  
3. From response: `task_id = data.task_id`.  
4. `task_logs(task_id)` (or `task_logs(task_id, lines=100)`).  
5. Use `data.content` from task_logs for analysis.

**Run a long shell command**

1. `run("nmap -sV 192.168.1.1")` → response has `data.task_id`.  
2. `task_logs(task_id)` to read stdout/stderr.

**Check what is running**

1. `task_list()` → `data.tasks` with `task_id`, `status`, `command`, `output_file`.  
2. For any `task_id`, use `task_logs(task_id)` to read output; use `task_stop(task_id)` to stop.

---

## Anti-patterns

- **Using download_file for server logs or scan output** — Use **task_logs(task_id)** or **run("cat path")**.  
- **Ignoring `success`** — Always parse JSON and handle `success === false` and `error`.  
- **Assuming run() is always sync** — Long-running commands return `task_id`; use task_logs to get output.  
- **Deleting the active session** — Use **session_switch** to another session before **session_delete**.

---

## Reference

For exact parameters and enums, see [reference.md](reference.md) in this skill directory.
