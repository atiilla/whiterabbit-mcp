# INFORMATION:
# - Tool: SQLMap
# - Description: SQL injection vulnerability scanner
# - Usage: Detects and exploits SQL injection vulnerabilities in web applications
# - Parameters: url (required), data (optional)

import asyncio
import re
import subprocess
import logging
from typing import Any, Dict, List, Optional
import json
import uuid
from enum import Enum

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

tasks: Dict[str, Dict[str, Any]] = {}
SQLMAP_PATH = "sqlmap" # Path to the sqlmap executable


class ScanStatus(Enum):
    QUEUED = "queued"      # Queued
    RUNNING = "running"    # Running
    COMPLETED = "completed" # Completed
    FAILED = "failed"      # Failed


async def run_sqlmap_scan(task_id: str, target_url: str, options: Dict[str, Any]) -> None:
    try:

        if task_id not in tasks:
            return
        
        cmd = [SQLMAP_PATH, "-u", target_url, "--batch", "--disable-coloring"]

        if options:
            for key, value in options.items():
                if isinstance(value, bool) and value:
                    cmd.append(f"--{key}")
                elif isinstance(value, (int, float)):
                    cmd.append(f"--{key}={value}")
                elif isinstance(value, str):
                    cmd.append(f"--{key}={value}")

        tasks[task_id]["status"] = ScanStatus.RUNNING.value
        tasks[task_id]["command"] = " ".join(cmd)  # save the command used
        tasks[task_id]["output"] = ""  # initialize output buffer
        tasks[task_id]["critical_lines"] = []  # store critical findings
        tasks[task_id]["vulnerabilities"] = []  # store structured vulnerability information

        # create process
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # read output
        while True:
            stdout_line = await process.stdout.readline()
            if stdout_line:
                line = stdout_line.decode('utf-8', errors='ignore').rstrip()
                tasks[task_id]["output"] += line + "\n"

                # log the output
                if "[CRITICAL]" in line:
                    tasks[task_id]["critical_lines"].append(line)

                # check for vulnerabilities
                if "is vulnerable" in line and "parameter" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        param = parts[1].strip("'")
                        vuln_type = " ".join(parts[3:])
                        tasks[task_id]["vulnerabilities"].append({
                            "parameter": param,
                            "type": vuln_type
                        })

            # check for end of process
            stderr_line = await process.stderr.readline()
            if stderr_line:
                line = stderr_line.decode('utf-8', errors='ignore').rstrip()
                tasks[task_id]["output"] += "[ERROR] " + line + "\n"
                if "errors" not in tasks[task_id]:
                    tasks[task_id]["errors"] = []
                tasks[task_id]["errors"].append(line)
            # 检查进程是否已退出
            if process.stdout.at_eof() and process.stderr.at_eof():
                break

        # wait for process to complete
        return_code = await process.wait()

        # update task status
        if return_code == 0:
            tasks[task_id]["status"] = ScanStatus.COMPLETED.value
            # parse the scan results
            parse_scan_results_from_output(task_id)
        else:
            tasks[task_id]["status"] = ScanStatus.FAILED.value

        # save final information
        tasks[task_id]["return_code"] = return_code
        tasks[task_id]["end_time"] = asyncio.get_event_loop().time()

    except Exception as e:
        logger.error(f"Error running sqlmap scan for task {task_id}: {e}")
        if task_id in tasks:
            tasks[task_id]["status"] = ScanStatus.FAILED.value
            tasks[task_id]["error"] = str(e)
            tasks[task_id]["end_time"] = asyncio.get_event_loop().time()

async def ExecSqlmap(target_url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes a SQLMap scan on the given URL with optional extra arguments.

    Args:
        target_url (str): The URL to scan.
        options: additional sqlmap options (e.g. {"level": 3, "risk": 2})
    """
    task_id = str(uuid.uuid4())
    try:
        # Start scanning in the background
        tasks[task_id] = {
            "status": ScanStatus.QUEUED.value,
            "target_url": target_url,
            "options": options or {},
            "start_time": asyncio.get_event_loop().time(),
            "output": "",
            "results": None
        }

        # Start the scan in a separate task
        asyncio.create_task(run_sqlmap_scan(task_id, target_url, options or {}))

        return {
            "task_id": task_id,
            "message": f"Scanning has begun {target_url}",
            "status_url": f"/scan/status/{task_id}"
        }

    except Exception as e:
        return {
            "task_id": task_id,
            "error": f"Failed to start scan: {str(e)}",
            "status": ScanStatus.FAILED.value
        }



def parse_scan_results_from_output(task_id: str) -> None:
    """Improved sqlmap output parser to handle various formats"""
    try:
        if "output" not in tasks[task_id]:
            return

        output = tasks[task_id]["output"]
        results = []

        # 1. Extracting Injection Points with More Flexible Regular Expressions
        injection_points = re.findall(
            r"Parameter: (.+?) \(.+?\)\n((?:\s+Type: .+?\n\s+Title: .+?\n\s+Payload: .+?\n)+)",
            output,
            re.DOTALL
        )

        for param, vuln_block in injection_points:
            # Extracting each vulnerability from the block
            vulns = re.findall(
                r"\s+Type: (.+?)\n\s+Title: (.+?)\n\s+Payload: (.+?)\n",
                vuln_block,
                re.DOTALL
            )
            for vuln in vulns:
                vuln_type, title, payload = vuln
                results.append({
                    "parameter": param,
                    "type": vuln_type.strip(),
                    "title": title.strip(),
                    "payload": payload.strip()
                })

        # 2. Handling Alternative Patterns for Newer Versions of SQLMap
        if not results:
            alt_points = re.findall(
                r"(\w+) parameter '(.+?)' (is vulnerable.+)",
                output
            )
            for method, param, details in alt_points:
                results.append({
                    "parameter": param,
                    "type": f"{method} - {details}"
                })

        # 3. Extracting Database Information
        db_info = re.search(
            r"back-end DBMS: (.+?)\n",
            output
        )
        if db_info:
            results.append({
                "type": "DBMS",
                "info": db_info.group(1).strip()
            })

        # 4. Adding Critical Lines as Fallback
        if "critical_lines" in tasks[task_id]:
            for line in tasks[task_id]["critical_lines"]:
                if "is vulnerable" in line:
                    results.append({
                        "type": "CRITICAL",
                        "info": line.replace("[CRITICAL] ", "")
                    })

        # 5. Adding Real-time Detected Vulnerabilities
        if "vulnerabilities" in tasks[task_id]:
            for vuln in tasks[task_id]["vulnerabilities"]:
                # Avoid duplicates
                if not any(r.get("parameter") == vuln["parameter"] for r in results):
                    results.append(vuln)

        if results:
            tasks[task_id]["results"] = results

    except Exception as e:
        if task_id in tasks:
            tasks[task_id]["parse_error"] = str(e)


async def get_scan_status(task_id: str) -> Dict[str, Any]:
    """Get the status of a scan task
    
    Args:
        task_id: ID of the scan task
    """
    if task_id not in tasks:
        return {"error": "Invalid task ID"}

    task = tasks[task_id]
    status = {
        "task_id": task_id,
        "status": task["status"],
        "target_url": task["target_url"],
    }

    # Add time information
    current_time = asyncio.get_event_loop().time()
    if "start_time" in task:
        elapsed = current_time - task["start_time"]
        status["elapsed_time"] = f"{elapsed:.2f}s"

    # Add results or error information
    if "results" in task and task["results"]:
        status["results"] = task["results"]

    # For running tasks, display partial output
    if task["status"] == ScanStatus.RUNNING.value and "output" in task:
        # Display the last 20 lines of output
        lines = task["output"].splitlines()
        status["partial_output"] = "\n".join(lines[-20:])

    # For completed tasks, display summary
    if task["status"] == ScanStatus.COMPLETED.value:
        if "output" in task:
            # Extract summary information
            summary = re.search(
                r"sqlmap identified the following injection point\(s\):(.+?)\n\n",
                task["output"],
                re.DOTALL
            )
            if summary:
                status["summary"] = summary.group(1).strip()
            else:
                status["summary"] = "No vulnerabilities found" if not task.get("results") else "Vulnerabilities detected"

    # For failed tasks, display error details
    if task["status"] == ScanStatus.FAILED.value:
        if "error" in task:
            status["error"] = task["error"]
        elif "errors" in task and task["errors"]:
            status["error"] = task["errors"][-1]  # Display the last error
        elif "output" in task:
            # Try to find errors in the output
            error_match = re.search(r"\[ERROR\] (.+)", task["output"])
            if error_match:
                status["error"] = error_match.group(1)

    # Add debug information
    if "command" in task:
        status["command"] = task["command"]

    return status


async def list_scans(include_completed: bool = True) -> Dict[str, Any]:
    """List all scan tasks

    Args:
        include_completed: Whether to include completed tasks
    """
    active_tasks = []
    completed_tasks = []

    for task_id, task in tasks.items():
        task_info = {
            "task_id": task_id,
            "status": task["status"],
            "target_url": task["target_url"],
            "start_time": task.get("start_time", 0)
        }

        if task["status"] in [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]:
            active_tasks.append(task_info)
        elif include_completed and task["status"] in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value]:
            task_info["end_time"] = task.get("end_time", 0)
            completed_tasks.append(task_info)

    return {
        "active_tasks": active_tasks,
        "completed_tasks": completed_tasks
    }


async def ExecSqlmap(
    url: str,
    data: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Wrapper for running Sqlmap vulnerability scanning.
    
    This function serves as an adapter between the MCP interface and the internal
    implementation. It processes command-line style arguments from the MCP call
    and converts them to the options dictionary format needed by the internal implementation.
    
    Args:
        url (str): The URL to scan for SQL injection vulnerabilities
        data (Optional[List[str]]): Additional sqlmap arguments passed as a list of strings
                                   (e.g. ['--data', 'id=1', '--level', '3'])
    
    Returns:
        Dict[str, Any]: Task information including task_id, message and status_url
    """
    # Convert the data list arguments into a dictionary of options
    options = {}
    if data and isinstance(data, list):
        # Process pairs of arguments (--option value)
        i = 0
        while i < len(data):
            if isinstance(data[i], str) and data[i].startswith('--'):
                option_name = data[i][2:]  # Remove the '--' prefix
                if i + 1 < len(data) and not str(data[i + 1]).startswith('--'):
                    options[option_name] = data[i + 1]
                    i += 2
                else:
                    # Flag without value
                    options[option_name] = True
                    i += 1
            else:
                i += 1
    
    # Use the main internal implementation with the processed options
    task_id = str(uuid.uuid4())
    try:
        # Start scanning in the background
        tasks[task_id] = {
            "status": ScanStatus.QUEUED.value,
            "target_url": url,
            "options": options,
            "start_time": asyncio.get_event_loop().time(),
            "output": "",
            "results": None
        }

        # Start the scan in a separate task
        asyncio.create_task(run_sqlmap_scan(task_id, url, options))

        return {
            "task_id": task_id,
            "message": f"Scanning has begun {url}",
            "status_url": f"/scan/status/{task_id}"
        }

    except Exception as e:
        return {
            "task_id": task_id,
            "error": f"Failed to start scan: {str(e)}",
            "status": ScanStatus.FAILED.value
        }
