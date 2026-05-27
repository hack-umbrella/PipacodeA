#!/usr/bin/env python3
"""
Unified Audit Engine — jar-analyzer + CodeQL Integration

Three-phase pipeline:
  Phase 1: Parallel data collection (jar-analyzer call graph + CFR decompile)
  Phase 2: Deep analysis (jar-analyzer quick scan + CodeQL taint analysis)
  Phase 3: Correlation engine (reachability verification + confidence scoring)
"""

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


# ============================================================
# Constants
# ============================================================

PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent.parent
ENGINE_JAR = PLUGIN_DIR / "bin" / "jar-analyzer-engine-1.2.0.jar"
SINK_JSON = PLUGIN_DIR / "references" / "dfs-sink.json"
SCHEMA_SQL = Path(__file__).resolve().parent / "schema.sql"

# CodeQL query paths
CODEQL_SECURITY_QUERIES = Path.home() / ".codeql/packages/codeql/java-queries/1.11.3/Security"

# Severity mapping for vuln types
VULN_SEVERITY = {
    "sqli": "critical",
    "rce": "critical",
    "deser": "critical",
    "ssti": "critical",
    "ssrf": "high",
    "xss": "high",
    "xxe": "high",
    "lfi": "high",
    "auth_bypass": "high",
    "log_injection": "medium",
    "crypto": "medium",
    "csrf": "medium",
    "idor": "medium",
    "hardcoded_credentials": "medium",
    "info_disclosure": "low",
    "weak_random": "low",
}

# CWE mapping for vuln types
VULN_CWE = {
    "sqli": "CWE-89",
    "rce": "CWE-78",
    "deser": "CWE-502",
    "ssti": "CWE-94",
    "ssrf": "CWE-918",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "lfi": "CWE-22",
    "auth_bypass": "CWE-287",
    "log_injection": "CWE-117",
    "crypto": "CWE-327",
    "csrf": "CWE-352",
    "idor": "CWE-639",
    "hardcoded_credentials": "CWE-798",
    "info_disclosure": "CWE-200",
    "weak_random": "CWE-330",
}

# CodeQL query ID to vuln type mapping
CODEQL_QUERY_MAP = {
    "java/sql-injection": "sqli",
    "java/sql-injection/unvalidated-url": "sqli",
    "java/command-line-injection": "rce",
    "java/unsafe-deserialization": "deser",
    "java/ssrf": "ssrf",
    "java/xss": "xss",
    "java/reflected-xss": "xss",
    "java/stored-xss": "xss",
    "java/xxe": "xxe",
    "java/path-injection": "lfi",
    "java/log-injection": "log_injection",
    "java/broken-crypto-algorithm": "crypto",
    "java/insufficient-key-size": "crypto",
    "java/insecure-random": "weak_random",
    "java/hardcoded-credential-api-call": "hardcoded_credentials",
    "java/hardcoded-password-field": "hardcoded_credentials",
    "java/csrf": "csrf",
    "java/cleartext-storage-cookie": "info_disclosure",
    "java/cleartext-credentials": "info_disclosure",
    "java/sensitive-get-query": "info_disclosure",
    # CWE-based
    "CWE-078": "rce",
    "CWE-089": "sqli",
    "CWE-090": "lfi",  # LDAP injection
    "CWE-094": "ssti",
    "CWE-079": "xss",
    "CWE-117": "log_injection",
    "CWE-200": "info_disclosure",
    "CWE-327": "crypto",
    "CWE-352": "csrf",
    "CWE-502": "deser",
    "CWE-601": "ssrf",  # URL redirect
    "CWE-611": "xxe",
    "CWE-917": "ssti",  # OGNL injection
    "CWE-918": "ssrf",
}

# Sink definitions from dfs-sink.json mapped to vuln types
SINK_TYPE_MAP = {
    "Runtime.exec": "rce",
    "ProcessBuilder.start": "rce",
    "ScriptEngine.eval": "ssti",
    "InitialContext.lookup": "rce",  # JNDI injection
    "Context.lookup": "rce",
    "Statement.execute": "sqli",
    "Statement.executeQuery": "sqli",
    "Statement.executeUpdate": "sqli",
    "Connection.prepareStatement": "sqli",
    "Connection.prepareCall": "sqli",
    "ObjectInputStream.readObject": "deser",
    "ObjectInputStream.readUnshared": "deser",
    "XMLDecoder.readObject": "deser",
    "Yaml.load": "deser",
    "Yaml.loadAs": "deser",
    "JSON.parseObject": "deser",
    "JSON.parse": "deser",
    "ObjectMapper.readValue": "deser",
    "HessianInput.readObject": "deser",
    "XStream.fromXML": "deser",
    "URL.openConnection": "ssrf",
    "HttpURLConnection.connect": "ssrf",
    "FileInputStream.new": "lfi",
    "FileOutputStream.new": "lfi",
    "File.delete": "lfi",
}


# ============================================================
# Data Classes
# ============================================================

@dataclass
class CodeQLFinding:
    cf_id: int = 0
    run_id: int = 0
    query_id: str = ""
    query_name: str = ""
    cwe_id: str = ""
    vuln_type: str = ""
    severity: str = "medium"
    message: str = ""
    source_class: str = ""
    source_method: str = ""
    source_file: str = ""
    source_line: int = 0
    source_col: int = 0
    sink_class: str = ""
    sink_method: str = ""
    sink_file: str = ""
    sink_line: int = 0
    sink_col: int = 0
    taint_path: str = ""
    sarif_rule_id: str = ""
    sarif_level: str = ""


@dataclass
class CallChain:
    cc_id: int = 0
    cf_id: int = 0
    entry_class: str = ""
    entry_method: str = ""
    entry_path: str = ""
    entry_http_method: str = ""
    chain: str = "[]"
    chain_depth: int = 0
    app_class_count: int = 0
    dep_class_count: int = 0
    is_reachable: int = 0
    reachability_score: float = 0.0


@dataclass
class UnifiedFinding:
    uf_id: int = 0
    vuln_type: str = ""
    severity: str = "medium"
    cwe_id: str = ""
    title: str = ""
    description: str = ""
    class_name: str = ""
    method_name: str = ""
    method_desc: str = ""
    source_file: str = ""
    line_number: int = 0
    codeql_cf_id: int = 0
    codeql_confidence: float = 0.0
    codeql_taint_path: str = ""
    ja_cc_id: int = 0
    ja_entry_path: str = ""
    ja_call_chain: str = ""
    ja_reachable: int = 0
    ja_spring_route: str = ""
    overall_confidence: float = 0.0
    verification_status: str = "unverified"
    exploit_hint: str = ""
    code_snippet: str = ""
    poc_template: str = ""
    evidence_hash: str = ""


# ============================================================
# Utility Functions
# ============================================================

def dot_to_jvm(class_name: str) -> str:
    """Convert dot-notation class name to JVM internal format."""
    return class_name.replace(".", "/")


def jvm_to_dot(class_name: str) -> str:
    """Convert JVM internal class name to dot notation."""
    return class_name.replace("/", ".")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def log(msg: str, level: str = "INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def run_cmd(cmd: list, cwd: str = None, timeout: int = 600) -> tuple:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


# ============================================================
# Phase 1: Data Collection
# ============================================================

class DataCollector:
    """Phase 1: Build jar-analyzer DB + CFR decompile."""

    def __init__(self, target_jar: str, work_dir: str, ja_db_path: str):
        self.target_jar = Path(target_jar).resolve()
        self.work_dir = Path(work_dir)
        self.ja_db_path = Path(ja_db_path)
        self.extracted_dir = self.work_dir / "extracted"
        self.decompiled_dir = self.work_dir / "decompiled"
        self.app_classes_jar = self.work_dir / "app-classes.jar"
        self.cfr_jar = self.work_dir / "cfr.jar"

    def run(self):
        log("=== Phase 1: Data Collection ===")
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: jar-analyzer DB (if not exists)
        if self.ja_db_path.exists():
            log(f"jar-analyzer DB already exists: {self.ja_db_path}")
        else:
            self._build_ja_db()

        # Step 2: Extract FatJar
        self._extract_jar()

        # Step 3: CFR decompile
        self._decompile()

        log("Phase 1 complete")

    def _build_ja_db(self):
        log("Building jar-analyzer database...")
        cmd = ["java", "-jar", str(ENGINE_JAR), "-j", str(self.target_jar)]
        rc, out, err = run_cmd(cmd, cwd=str(self.work_dir), timeout=1200)
        if rc != 0:
            log(f"jar-analyzer failed: {err}", "ERROR")
            raise RuntimeError(f"jar-analyzer-engine failed with code {rc}")
        # Move DB to work_dir if created in cwd
        default_db = Path.cwd() / "jar-analyzer.db"
        if default_db.exists() and not self.ja_db_path.exists():
            shutil.move(str(default_db), str(self.ja_db_path))
        log(f"jar-analyzer DB: {self.ja_db_path}")

    def _extract_jar(self):
        if self.extracted_dir.exists():
            log("Already extracted, skipping")
            return
        log("Extracting FatJar...")
        self.extracted_dir.mkdir(parents=True, exist_ok=True)
        cmd = ["jar", "xf", str(self.target_jar)]
        rc, out, err = run_cmd(cmd, cwd=str(self.extracted_dir))
        if rc != 0:
            log(f"jar extract failed: {err}", "ERROR")
            raise RuntimeError("jar extract failed")

        # Create app-classes.jar from BOOT-INF/classes
        classes_dir = self.extracted_dir / "BOOT-INF" / "classes"
        if classes_dir.exists():
            log("Creating app-classes.jar from BOOT-INF/classes...")
            cmd = ["jar", "cf", str(self.app_classes_jar), "-C", str(classes_dir), "."]
            rc, out, err = run_cmd(cmd)
            if rc != 0:
                log(f"jar create failed: {err}", "WARN")

    def _ensure_cfr(self):
        if self.cfr_jar.exists():
            return
        log("Downloading CFR decompiler...")
        import urllib.request
        url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
        urllib.request.urlretrieve(url, str(self.cfr_jar))
        log("CFR downloaded")

    def _decompile(self):
        if self.decompiled_dir.exists() and any(self.decompiled_dir.rglob("*.java")):
            count = len(list(self.decompiled_dir.rglob("*.java")))
            log(f"Already decompiled ({count} files), skipping")
            return

        self._ensure_cfr()
        log("Decompiling application classes with CFR...")

        jar_to_decompile = self.app_classes_jar
        if not jar_to_decompile.exists():
            # Fall back to the original JAR
            jar_to_decompile = self.target_jar

        cmd = ["java", "-jar", str(self.cfr_jar), str(jar_to_decompile),
               "--outputdir", str(self.decompiled_dir)]
        rc, out, err = run_cmd(cmd, timeout=300)
        if rc != 0:
            log(f"CFR decompile failed: {err}", "ERROR")
            raise RuntimeError("CFR decompile failed")

        count = len(list(self.decompiled_dir.rglob("*.java")))
        log(f"Decompiled {count} Java files to {self.decompiled_dir}")


# ============================================================
# Phase 2: Analysis Engines
# ============================================================

class CodeQLAnalyzer:
    """Build CodeQL database and run security queries."""

    def __init__(self, work_dir: str, decompiled_dir: str):
        self.work_dir = Path(work_dir)
        self.decompiled_dir = Path(decompiled_dir)
        self.codeql_db = self.work_dir / "codeql-db"
        self.results_dir = self.work_dir / "codeql-results"

    def run(self) -> list:
        log("=== Phase 2a: CodeQL Analysis ===")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Check CodeQL availability
        rc, out, err = run_cmd(["codeql", "--version"])
        if rc != 0:
            log("CodeQL CLI not found, skipping CodeQL analysis", "WARN")
            return []

        # Build database
        self._build_db()

        # Run queries
        findings = self._run_queries()

        log(f"CodeQL found {len(findings)} raw findings")
        return findings

    def _build_db(self):
        if self.codeql_db.exists():
            log("CodeQL DB already exists, rebuilding...")
            shutil.rmtree(self.codeql_db)

        log("Building CodeQL database (buildless mode)...")
        cmd = [
            "codeql", "database", "create",
            str(self.codeql_db),
            "--language=java",
            "--extractor-option=java.buildless=true",
            f"--source-root={self.decompiled_dir}",
        ]
        rc, out, err = run_cmd(cmd, timeout=600)
        if rc != 0:
            log(f"CodeQL DB creation failed: {err}", "ERROR")
            raise RuntimeError("CodeQL database creation failed")
        log("CodeQL database created")

    def _run_queries(self) -> list:
        findings = []

        # Run all security queries
        if not CODEQL_SECURITY_QUERIES.exists():
            log(f"Security queries not found: {CODEQL_SECURITY_QUERIES}", "WARN")
            return findings

        log("Running CodeQL security queries...")
        sarif_file = self.results_dir / "security.sarif"

        cmd = [
            "codeql", "database", "analyze",
            str(self.codeql_db),
            str(CODEQL_SECURITY_QUERIES),
            "--format=sarif-latest",
            f"--output={sarif_file}",
            "--threads=0",
        ]
        rc, out, err = run_cmd(cmd, timeout=600)

        if sarif_file.exists():
            findings = self._parse_sarif(sarif_file)
        else:
            # Try BQRS fallback
            findings = self._parse_bqrs_results()

        return findings

    def _parse_sarif(self, sarif_file: Path) -> list:
        findings = []
        try:
            with open(sarif_file) as f:
                sarif = json.load(f)

            rules_map = {}
            for run in sarif.get("runs", []):
                driver = run.get("tool", {}).get("driver", {})
                for rule in driver.get("rules", []):
                    rules_map[rule["id"]] = rule

                for result in run.get("results", []):
                    finding = self._sarif_result_to_finding(result, rules_map)
                    if finding:
                        findings.append(finding)
        except Exception as e:
            log(f"SARIF parse error: {e}", "ERROR")

        return findings

    def _sarif_result_to_finding(self, result: dict, rules_map: dict) -> Optional[CodeQLFinding]:
        rule_id = result.get("ruleId", "")
        rule = rules_map.get(rule_id, {})

        # Map to vuln type
        vuln_type = CODEQL_QUERY_MAP.get(rule_id, "")
        if not vuln_type:
            # Try CWE from rule
            cwe_ids = rule.get("properties", {}).get("tags", [])
            for tag in cwe_ids:
                if tag.startswith("external/cwe/cwe-"):
                    cwe_num = tag.split("-")[-1]
                    vuln_type = CODEQL_QUERY_MAP.get(f"CWE-{cwe_num}", "")
                    if vuln_type:
                        break

        if not vuln_type:
            return None  # Skip non-security findings

        # Extract locations
        locations = result.get("locations", [])
        source_class = ""
        source_method = ""
        source_file = ""
        source_line = 0

        if locations:
            loc = locations[0]
            phys = loc.get("physicalLocation", {})
            source_file = phys.get("artifactLocation", {}).get("uri", "")
            source_line = phys.get("region", {}).get("startLine", 0)

            # Extract class/method from logical location
            logical = loc.get("logicalLocations", [])
            if logical:
                source_class = logical[0].get("fullyQualifiedName", "")
                source_method = logical[0].get("name", "")

        # Extract sink from related locations
        sink_class = ""
        sink_method = ""
        sink_file = ""
        sink_line = 0
        related = result.get("relatedLocations", [])
        if related:
            rloc = related[0]
            sink_file = rloc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            sink_line = rloc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
            rlogical = rloc.get("logicalLocations", [])
            if rlogical:
                sink_class = rlogical[0].get("fullyQualifiedName", "")
                sink_method = rlogical[0].get("name", "")

        # Message
        msg_obj = result.get("message", {})
        message = msg_obj.get("text", "")

        cwe_id = VULN_CWE.get(vuln_type, "")
        severity = VULN_SEVERITY.get(vuln_type, "medium")

        return CodeQLFinding(
            query_id=rule_id,
            query_name=rule.get("shortDescription", {}).get("text", rule_id),
            cwe_id=cwe_id,
            vuln_type=vuln_type,
            severity=severity,
            message=message,
            source_class=source_class,
            source_method=source_method,
            source_file=source_file,
            source_line=source_line,
            sink_class=sink_class,
            sink_method=sink_method,
            sink_file=sink_file,
            sink_line=sink_line,
            sarif_rule_id=rule_id,
            sarif_level=result.get("level", ""),
        )

    def _parse_bqrs_results(self) -> list:
        """Fallback: parse BQRS files directly."""
        findings = []
        bqrs_dir = self.codeql_db / "results"
        if not bqrs_dir.exists():
            return findings

        for bqrs_file in bqrs_dir.rglob("*.bqrs"):
            try:
                cmd = ["codeql", "bqrs", "decode", "--format=csv",
                       "--entities=all", str(bqrs_file)]
                rc, out, err = run_cmd(cmd, timeout=30)
                if rc != 0:
                    continue

                lines = out.strip().split("\n")
                if len(lines) <= 1:
                    continue

                # Extract query name from path
                query_name = bqrs_file.stem
                cwe_match = re.search(r"CWE-(\d+)", str(bqrs_file))
                cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

                vuln_type = CODEQL_QUERY_MAP.get(cwe_id, "")
                if not vuln_type:
                    vuln_type = CODEQL_QUERY_MAP.get(query_name, "")

                if not vuln_type:
                    continue

                for line in lines[1:]:
                    if not line.strip():
                        continue
                    finding = self._csv_line_to_finding(
                        line, query_name, cwe_id, vuln_type, bqrs_file
                    )
                    if finding:
                        findings.append(finding)
            except Exception as e:
                log(f"BQRS parse error for {bqrs_file}: {e}", "WARN")

        return findings

    def _csv_line_to_finding(self, line: str, query_name: str,
                              cwe_id: str, vuln_type: str, bqrs_file: Path) -> Optional[CodeQLFinding]:
        """Parse a CSV line from BQRS decode into a CodeQLFinding."""
        # CSV fields: typically [expr, source, sink, message, source_name, source_desc]
        # with URL fields interspersed
        parts = []
        current = ""
        in_quote = False
        for ch in line:
            if ch == '"':
                in_quote = not in_quote
            elif ch == ',' and not in_quote:
                parts.append(current.strip('"'))
                current = ""
            else:
                current += ch
        parts.append(current.strip('"'))

        # Extract file locations from URL fields
        file_urls = re.findall(r'file://([^"]+)', line)
        source_file = ""
        source_line = 0
        if file_urls:
            # Format: /path/to/File.java:line:col:line:col
            loc = file_urls[0]
            parts_split = loc.split(":")
            source_file = parts_split[0]
            if len(parts_split) > 1:
                try:
                    source_line = int(parts_split[1])
                except ValueError:
                    pass

        # Extract class name from file path
        source_class = ""
        if source_file:
            # Convert file path to class name
            # /path/to/decompiled/com/example/MyClass.java -> com.example.MyClass
            match = re.search(r'decompiled/(.+)\.java$', source_file)
            if match:
                source_class = dot_to_jvm(match.group(1))

        message = parts[3] if len(parts) > 3 else ""

        return CodeQLFinding(
            query_id=query_name,
            query_name=query_name,
            cwe_id=cwe_id,
            vuln_type=vuln_type,
            severity=VULN_SEVERITY.get(vuln_type, "medium"),
            message=message,
            source_class=source_class,
            source_file=source_file,
            source_line=source_line,
        )


class JAScanner:
    """jar-analyzer quick scan: find Sinks and trace call chains."""

    def __init__(self, ja_db_path: str, target_jar: str = ""):
        self.ja_db_path = Path(ja_db_path)
        self.target_jar = Path(target_jar) if target_jar else Path()
        self.conn = None
        self.sinks = []
        self._load_sinks()

    def _load_sinks(self):
        if SINK_JSON.exists():
            with open(SINK_JSON) as f:
                self.sinks = json.load(f)

    def connect(self):
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.ja_db_path))
            self.conn.row_factory = sqlite3.Row

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def find_sinks(self) -> list:
        """Find all Sink call sites in the codebase."""
        self.connect()
        results = []

        for sink in self.sinks:
            cls = sink["className"]
            method = sink["methodName"]
            desc = sink.get("methodDesc", "")

            query = """
                SELECT caller_class_name, caller_method_name, caller_method_desc,
                       callee_class_name, callee_method_name, callee_method_desc,
                       op_code
                FROM method_call_table
                WHERE callee_class_name = ? AND callee_method_name = ?
            """
            params = [cls, method]
            if desc:
                query += " AND callee_method_desc = ?"
                params.append(desc)

            rows = self.conn.execute(query, params).fetchall()
            for row in rows:
                vuln_type = SINK_TYPE_MAP.get(f"{sink['boxName'].split('(')[0]}", "")
                results.append({
                    "box_name": sink["boxName"],
                    "vuln_type": vuln_type,
                    "caller_class": row["caller_class_name"],
                    "caller_method": row["caller_method_name"],
                    "caller_desc": row["caller_method_desc"],
                    "sink_class": row["callee_class_name"],
                    "sink_method": row["callee_method_name"],
                })

        return results

    def get_spring_routes(self) -> list:
        """Get all Spring MVC routes."""
        self.connect()
        rows = self.conn.execute("""
            SELECT path, restful_type, class_name, method_name, method_desc
            FROM spring_method_table
        """).fetchall()
        return [dict(r) for r in rows]

    def trace_call_chain(self, target_class: str, target_method: str,
                          max_depth: int = 6) -> list:
        """Trace callers of a method recursively up to max_depth."""
        self.connect()
        chains = []

        # Use GROUP BY to deduplicate cycles (SQLite lacks CYCLE clause)
        query = """
            WITH RECURSIVE call_chain AS (
                SELECT caller_class_name, caller_method_name, caller_method_desc,
                       callee_class_name, callee_method_name, callee_method_desc,
                       1 AS depth,
                       callee_class_name || '.' || callee_method_name AS visited
                FROM method_call_table
                WHERE callee_class_name = ? AND callee_method_name = ?
                UNION ALL
                SELECT mc.caller_class_name, mc.caller_method_name, mc.caller_method_desc,
                       mc.callee_class_name, mc.callee_method_name, mc.callee_method_desc,
                       cc.depth + 1,
                       cc.visited || '|' || mc.callee_class_name || '.' || mc.callee_method_name
                FROM method_call_table mc
                JOIN call_chain cc ON mc.callee_class_name = cc.caller_class_name
                                  AND mc.callee_method_name = cc.caller_method_name
                                  AND mc.callee_method_desc = cc.caller_method_desc
                WHERE cc.depth < ?
                  AND cc.visited NOT LIKE '%' || mc.callee_class_name || '.' || mc.callee_method_name || '%'
            )
            SELECT * FROM call_chain ORDER BY depth
        """

        rows = self.conn.execute(query, (target_class, target_method, max_depth)).fetchall()

        if rows:
            # Group by entry point (depth=1 callers)
            chain_map = defaultdict(list)
            for row in rows:
                key = (row["caller_class_name"], row["caller_method_name"])
                chain_map[key].append(dict(row))

            # Find which chains lead to Spring controllers
            routes = self.get_spring_routes()
            route_map = {}
            for r in routes:
                route_map[(r["class_name"], r["method_name"])] = r

            for (caller_cls, caller_mth), chain_rows in chain_map.items():
                # Check if any caller in the chain is a controller
                entry_route = route_map.get((caller_cls, caller_mth))
                if not entry_route:
                    # Walk up the chain to find the entry point
                    for row in chain_rows:
                        key = (row["caller_class_name"], row["caller_method_name"])
                        entry_route = route_map.get(key)
                        if entry_route:
                            break

                if entry_route:
                    chain_data = []
                    for row in chain_rows:
                        chain_data.append({
                            "caller_class": row["caller_class_name"],
                            "caller_method": row["caller_method_name"],
                            "callee_class": row["callee_class_name"],
                            "callee_method": row["callee_method_name"],
                        })

                    chains.append(CallChain(
                        entry_class=entry_route["class_name"],
                        entry_method=entry_route["method_name"],
                        entry_path=entry_route.get("path", ""),
                        entry_http_method=entry_route.get("restful_type", ""),
                        chain=json.dumps(chain_data),
                        chain_depth=len(chain_data),
                        is_reachable=1,
                    ))

        return chains

    def find_auth_gaps(self) -> list:
        """Find controllers without authentication annotations."""
        self.connect()
        gaps = []

        # Get all controller methods
        controllers = self.conn.execute("""
            SELECT class_name FROM spring_controller_table
        """).fetchall()

        for ctrl in controllers:
            cls = ctrl["class_name"]
            methods = self.conn.execute("""
                SELECT method_name, method_desc, path, restful_type
                FROM spring_method_table WHERE class_name = ?
            """, (cls,)).fetchall()

            for method in methods:
                # Check for auth annotations
                annos = self.conn.execute("""
                    SELECT anno_name FROM anno_table
                    WHERE class_name = ? AND (method_name = ? OR method_name IS NULL)
                """, (cls, method["method_name"])).fetchall()

                auth_keywords = ["PreAuthorize", "Secured", "RolesAllowed",
                                 "RequiresAuthentication", "RequiresRoles",
                                 "RequiresPermissions", "Authenticated"]
                has_auth = any(
                    any(kw in a["anno_name"] for kw in auth_keywords)
                    for a in annos
                )

                if not has_auth:
                    gaps.append({
                        "class_name": cls,
                        "method_name": method["method_name"],
                        "path": method["path"],
                        "http_method": method["restful_type"],
                    })

        return gaps


# ============================================================
# Phase 3: Correlation Engine
# ============================================================

class CorrelationEngine:
    """Merge CodeQL findings with jar-analyzer call graph data."""

    def __init__(self, ja_db_path: str, work_dir: str):
        self.ja_db_path = Path(ja_db_path)
        self.work_dir = Path(work_dir)
        self.conn = None
        self._ja_scanner = JAScanner(str(ja_db_path))
        self._ja_scanner.connect()

    def connect(self):
        self.conn = sqlite3.connect(str(self.ja_db_path))
        self.conn.row_factory = sqlite3.Row
        # Initialize schema extension
        schema_sql = SCHEMA_SQL.read_text()
        self.conn.executescript(schema_sql)
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()
        if self._ja_scanner:
            self._ja_scanner.close()

    def correlate(self, codeql_findings: list, ja_sinks: list,
                   ja_routes: list, auth_gaps: list) -> list:
        log("=== Phase 3: Correlation ===")
        self.connect()
        unified = []

        # Step 1: Store CodeQL findings and verify reachability
        for cf in codeql_findings:
            cf_id = self._store_codeql_finding(cf)

            # Find matching Spring route via jar-analyzer
            chain = self._verify_reachability(cf, ja_routes)
            if chain:
                chain.cf_id = cf_id
                cc_id = self._store_call_chain(chain)

                uf = self._create_unified_finding(cf, chain, cc_id)
                unified.append(uf)
            else:
                # No call chain found, still record as unverified
                uf = self._create_unified_finding(cf, None, 0)
                unified.append(uf)

        # Step 2: Check jar-analyzer sinks that CodeQL didn't find
        codeql_classes = {f.source_class for f in codeql_findings if f.source_class}
        for sink in ja_sinks:
            caller_jvm = sink["caller_class"]
            if caller_jvm in codeql_classes:
                continue  # Already covered by CodeQL

            # This is a sink not covered by CodeQL — lower confidence
            chains = self._trace_ja_sink(sink, ja_routes)
            for chain in chains:
                vuln_type = sink.get("vuln_type", "unknown")
                if not vuln_type:
                    continue

                uf = UnifiedFinding(
                    vuln_type=vuln_type,
                    severity=VULN_SEVERITY.get(vuln_type, "medium"),
                    cwe_id=VULN_CWE.get(vuln_type, ""),
                    title=f"Potential {vuln_type.upper()} via {sink['box_name']}",
                    description=f"Sink {sink['box_name']} called from {caller_jvm}.{sink['caller_method']}",
                    class_name=caller_jvm,
                    method_name=sink["caller_method"],
                    ja_entry_path=chain.entry_path,
                    ja_call_chain=chain.chain,
                    ja_reachable=chain.is_reachable,
                    ja_spring_route=f"{chain.entry_http_method} {chain.entry_path}",
                    overall_confidence=0.5 if chain.is_reachable else 0.2,
                    verification_status="probable" if chain.is_reachable else "possible",
                )
                unified.append(uf)

        # Step 3: Add auth bypass findings
        for gap in auth_gaps:
            uf = UnifiedFinding(
                vuln_type="auth_bypass",
                severity="high",
                cwe_id="CWE-287",
                title=f"Missing authentication: {gap['http_method']} {gap['path']}",
                description=f"Endpoint {gap['path']} has no authentication annotation",
                class_name=gap["class_name"],
                method_name=gap["method_name"],
                ja_entry_path=gap["path"],
                ja_spring_route=f"{gap['http_method']} {gap['path']}",
                overall_confidence=0.7,
                verification_status="probable",
            )
            unified.append(uf)

        # Step 4: Score and deduplicate
        unified = self._score_and_deduplicate(unified)

        # Step 5: Store unified findings
        for uf in unified:
            self._store_unified_finding(uf)

        self.conn.commit()
        self.close()

        log(f"Correlation complete: {len(unified)} unified findings")
        return unified

    def _store_codeql_finding(self, cf: CodeQLFinding) -> int:
        cursor = self.conn.execute("""
            INSERT INTO codeql_findings
            (run_id, query_id, query_name, cwe_id, vuln_type, severity, message,
             source_class, source_method, source_file, source_line, source_col,
             sink_class, sink_method, sink_file, sink_line, sink_col,
             taint_path, sarif_rule_id, sarif_level)
            VALUES (0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cf.query_id, cf.query_name, cf.cwe_id, cf.vuln_type, cf.severity,
            cf.message, cf.source_class, cf.source_method, cf.source_file,
            cf.source_line, cf.source_col, cf.sink_class, cf.sink_method,
            cf.sink_file, cf.sink_line, cf.sink_col, cf.taint_path,
            cf.sarif_rule_id, cf.sarif_level,
        ))
        return cursor.lastrowid

    def _store_call_chain(self, chain: CallChain) -> int:
        cursor = self.conn.execute("""
            INSERT INTO ja_call_chains
            (cf_id, entry_class, entry_method, entry_path, entry_http_method,
             chain, chain_depth, app_class_count, dep_class_count,
             is_reachable, reachability_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            chain.cf_id, chain.entry_class, chain.entry_method,
            chain.entry_path, chain.entry_http_method, chain.chain,
            chain.chain_depth, chain.app_class_count, chain.dep_class_count,
            chain.is_reachable, chain.reachability_score,
        ))
        return cursor.lastrowid

    def _store_unified_finding(self, uf: UnifiedFinding):
        # Compute evidence hash
        evidence_text = f"{uf.class_name}:{uf.method_name}:{uf.vuln_type}"
        uf.evidence_hash = sha256(evidence_text)

        self.conn.execute("""
            INSERT INTO unified_findings
            (vuln_type, severity, cwe_id, title, description,
             class_name, method_name, method_desc, source_file, line_number,
             codeql_cf_id, codeql_confidence, codeql_taint_path,
             ja_cc_id, ja_entry_path, ja_call_chain, ja_reachable, ja_spring_route,
             overall_confidence, verification_status, exploit_hint,
             code_snippet, poc_template, evidence_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uf.vuln_type, uf.severity, uf.cwe_id, uf.title, uf.description,
            uf.class_name, uf.method_name, uf.method_desc, uf.source_file,
            uf.line_number, uf.codeql_cf_id, uf.codeql_confidence,
            uf.codeql_taint_path, uf.ja_cc_id, uf.ja_entry_path,
            uf.ja_call_chain, uf.ja_reachable, uf.ja_spring_route,
            uf.overall_confidence, uf.verification_status, uf.exploit_hint,
            uf.code_snippet, uf.poc_template, uf.evidence_hash,
        ))

    def _verify_reachability(self, cf: CodeQLFinding, ja_routes: list) -> Optional[CallChain]:
        """Verify if a CodeQL finding is reachable from a web entry point."""
        if not cf.source_class:
            return None

        cls_jvm = dot_to_jvm(cf.source_class) if "." in cf.source_class else cf.source_class

        # Check if this class is directly a controller
        for route in ja_routes:
            if route["class_name"] == cls_jvm:
                return CallChain(
                    entry_class=route["class_name"],
                    entry_method=route["method_name"],
                    entry_path=route.get("path", ""),
                    entry_http_method=route.get("restful_type", ""),
                    chain=json.dumps([{
                        "caller_class": route["class_name"],
                        "caller_method": route["method_name"],
                        "callee_class": cls_jvm,
                        "callee_method": cf.source_method,
                    }]),
                    chain_depth=1,
                    is_reachable=1,
                    reachability_score=1.0,
                )

        # Trace call chain using jar-analyzer
        try:
            chains = self._ja_scanner.trace_call_chain(cls_jvm, cf.source_method)
            if chains:
                best = max(chains, key=lambda c: c.chain_depth)
                return best
        except Exception as e:
            log(f"Call chain trace error: {e}", "WARN")

        return None

    def _trace_ja_sink(self, sink: dict, ja_routes: list) -> list:
        """Trace a jar-analyzer sink back to web entry points."""
        try:
            return self._ja_scanner.trace_call_chain(sink["caller_class"], sink["caller_method"])
        except Exception:
            return []

    def _create_unified_finding(self, cf: CodeQLFinding,
                                 chain: Optional[CallChain], cc_id: int) -> UnifiedFinding:
        """Create a unified finding from CodeQL result + optional call chain."""
        # Confidence scoring
        codeql_conf = 0.8  # Base confidence for CodeQL findings

        if chain and chain.is_reachable:
            ja_conf = min(1.0, 1.0 / max(1, chain.chain_depth))
            # Both engines agree: high confidence
            overall = min(1.0, (codeql_conf + ja_conf) / 2 + 0.1)
            status = "confirmed" if overall >= 0.8 else "probable"
        elif chain:
            overall = codeql_conf * 0.7
            status = "possible"
        else:
            overall = codeql_conf * 0.5
            status = "unverified"

        # Generate exploit hint
        exploit_hint = self._generate_exploit_hint(cf)

        return UnifiedFinding(
            vuln_type=cf.vuln_type,
            severity=cf.severity if overall >= 0.5 else "low",
            cwe_id=cf.cwe_id,
            title=f"{cf.vuln_type.upper()}: {cf.query_name}",
            description=cf.message,
            class_name=cf.source_class,
            method_name=cf.source_method,
            source_file=cf.source_file,
            line_number=cf.source_line,
            codeql_cf_id=cf.cf_id,
            codeql_confidence=codeql_conf,
            codeql_taint_path=cf.taint_path,
            ja_cc_id=cc_id,
            ja_entry_path=chain.entry_path if chain else "",
            ja_call_chain=chain.chain if chain else "[]",
            ja_reachable=chain.is_reachable if chain else 0,
            ja_spring_route=f"{chain.entry_http_method} {chain.entry_path}" if chain else "",
            overall_confidence=overall,
            verification_status=status,
            exploit_hint=exploit_hint,
        )

    def _generate_exploit_hint(self, cf: CodeQLFinding) -> str:
        hints = {
            "sqli": "Try: ' OR '1'='1, UNION SELECT, time-based blind (SLEEP/BENCHMARK)",
            "rce": "Try: ;id, |whoami, `cmd`, $(cmd), Runtime.exec chain",
            "ssrf": "Try: http://169.254.169.254/latest/meta-data/, file:///etc/passwd",
            "xss": "Try: <script>alert(1)</script>, <img onerror=alert(1) src=x>",
            "xxe": "Try: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
            "deser": "Check for ysoserial gadget chains matching the target libraries",
            "lfi": "Try: ../../../etc/passwd, ..\\..\\windows\\win.ini",
            "ssti": "Try: ${7*7}, #{7*7}, {{7*7}}",
            "log_injection": "Try injecting CRLF to forge log entries",
            "crypto": "MD5/SHA1 are broken, consider collision attacks",
            "csrf": "Craft a cross-site form submission targeting this endpoint",
        }
        return hints.get(cf.vuln_type, "Manual verification recommended")

    def _score_and_deduplicate(self, findings: list) -> list:
        """Deduplicate and sort by confidence."""
        seen = set()
        unique = []
        for uf in findings:
            # Include source_file:line to distinguish multiple sinks in same method
            key = (uf.class_name, uf.method_name, uf.vuln_type, uf.source_file, uf.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(uf)

        # Sort: confirmed first, then by confidence
        status_order = {"confirmed": 0, "probable": 1, "possible": 2, "unverified": 3}
        unique.sort(key=lambda f: (status_order.get(f.verification_status, 9), -f.overall_confidence))
        return unique


# ============================================================
# Report Generator
# ============================================================

class ReportGenerator:
    """Generate unified audit report."""

    def __init__(self, work_dir: str, target_jar: str):
        self.work_dir = Path(work_dir)
        self.target_jar = target_jar

    def generate(self, findings: list) -> str:
        report_path = self.work_dir / "unified_audit_report.md"

        lines = [
            "# Unified Security Audit Report",
            f"**Target**: `{self.target_jar}`",
            f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Engine**: jar-analyzer + CodeQL (Correlation Engine)",
            "",
            "---",
            "",
            "## Summary",
            "",
        ]

        # Stats
        confirmed = [f for f in findings if f.verification_status == "confirmed"]
        probable = [f for f in findings if f.verification_status == "probable"]
        possible = [f for f in findings if f.verification_status == "possible"]
        unverified = [f for f in findings if f.verification_status == "unverified"]

        lines.extend([
            "| Status | Count |",
            "|:-------|:------|",
            f"| Confirmed (dual-engine) | {len(confirmed)} |",
            f"| Probable (single-engine + reachable) | {len(probable)} |",
            f"| Possible (single-engine) | {len(possible)} |",
            f"| Unverified | {len(unverified)} |",
            f"| **Total** | **{len(findings)}** |",
            "",
        ])

        # By vuln type
        type_counts = defaultdict(int)
        for f in findings:
            type_counts[f.vuln_type] += 1

        if type_counts:
            lines.extend([
                "### By Vulnerability Type",
                "",
                "| Type | Count | Severity | CWE |",
                "|:-----|:------|:---------|:----|",
            ])
            for vtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                sev = VULN_SEVERITY.get(vtype, "medium")
                cwe = VULN_CWE.get(vtype, "")
                lines.append(f"| {vtype.upper()} | {count} | {sev} | {cwe} |")
            lines.append("")

        # Detailed findings
        lines.extend(["---", "", "## Detailed Findings", ""])

        for i, f in enumerate(findings, 1):
            icon = {"confirmed": "[C]", "probable": "[P]", "possible": "[?]", "unverified": "[U]"}.get(f.verification_status, "")
            lines.extend([
                f"### {i}. {icon} {f.title}",
                "",
                f"- **Type**: {f.vuln_type.upper()}",
                f"- **Severity**: {f.severity}",
                f"- **Confidence**: {f.overall_confidence:.0%}",
                f"- **Status**: {f.verification_status}",
                f"- **CWE**: {f.cwe_id}",
                "",
            ])

            if f.class_name:
                lines.append(f"- **Location**: `{jvm_to_dot(f.class_name)}.{f.method_name}()` (line {f.line_number})")

            if f.ja_spring_route:
                lines.append(f"- **HTTP Entry**: `{f.ja_spring_route}`")

            if f.ja_call_chain and f.ja_call_chain != "[]":
                chain_data = json.loads(f.ja_call_chain)
                if chain_data:
                    lines.extend(["", "**Call Chain**:", "```"])
                    for step in chain_data:
                        lines.append(f"  {step.get('caller_class', '')}.{step.get('caller_method', '')} -> {step.get('callee_class', '')}.{step.get('callee_method', '')}")
                    lines.append("```")

            if f.exploit_hint:
                lines.extend(["", f"**Exploit Hint**: {f.exploit_hint}"])

            if f.description:
                lines.extend(["", f"**Description**: {f.description}"])

            lines.extend(["", "---", ""])

        # Auth gaps section
        auth_findings = [f for f in findings if f.vuln_type == "auth_bypass"]
        if auth_findings:
            lines.extend([
                "## Authentication Gaps",
                "",
                "| HTTP Method | Path | Class | Method |",
                "|:------------|:-----|:------|:-------|",
            ])
            for f in auth_findings:
                lines.append(f"| {f.ja_spring_route.split()[0] if f.ja_spring_route else '?'} | {f.ja_entry_path} | `{jvm_to_dot(f.class_name)}` | {f.method_name} |")
            lines.append("")

        report = "\n".join(lines)
        report_path.write_text(report)
        log(f"Report saved to: {report_path}")
        return str(report_path)


# ============================================================
# Main Pipeline
# ============================================================

class UnifiedAuditPipeline:
    """Orchestrate the full unified audit pipeline."""

    def __init__(self, target_jar: str, work_dir: str = None, skip_codeql: bool = False):
        self.target_jar = Path(target_jar).resolve()
        if not self.target_jar.exists():
            raise FileNotFoundError(f"Target JAR not found: {self.target_jar}")

        self.work_dir = Path(work_dir) if work_dir else Path.cwd() / "unified-audit-run"
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self.ja_db_path = self.work_dir / "jar-analyzer.db"
        self.skip_codeql = skip_codeql

    def run(self):
        start_time = time.time()
        log("=" * 60)
        log("Unified Security Audit Pipeline")
        log(f"Target: {self.target_jar}")
        log(f"Work dir: {self.work_dir}")
        log("=" * 60)

        # Phase 1: Data Collection
        collector = DataCollector(
            str(self.target_jar), str(self.work_dir), str(self.ja_db_path)
        )
        collector.run()

        # Phase 2a: CodeQL Analysis
        if self.skip_codeql:
            log("Skipping CodeQL analysis (--skip-codeql)")
            codeql_findings = []
        else:
            codeql = CodeQLAnalyzer(str(self.work_dir), str(collector.decompiled_dir))
            codeql_findings = codeql.run()

        # Phase 2b: jar-analyzer Sink Scan
        with JAScanner(str(self.ja_db_path), str(self.target_jar)) as scanner:
            ja_sinks = scanner.find_sinks()
            ja_routes = scanner.get_spring_routes()
            auth_gaps = scanner.find_auth_gaps()
            log(f"jar-analyzer: {len(ja_sinks)} sinks, {len(ja_routes)} routes, {len(auth_gaps)} auth gaps")

        # Phase 3: Correlation
        correlator = CorrelationEngine(str(self.ja_db_path), str(self.work_dir))
        unified_findings = correlator.correlate(
            codeql_findings, ja_sinks, ja_routes, auth_gaps
        )

        # Generate Report
        reporter = ReportGenerator(str(self.work_dir), str(self.target_jar))
        report_path = reporter.generate(unified_findings)

        elapsed = time.time() - start_time
        log("=" * 60)
        log(f"Audit complete in {elapsed:.1f}s")
        log(f"Findings: {len(unified_findings)}")
        log(f"  Confirmed: {len([f for f in unified_findings if f.verification_status == 'confirmed'])}")
        log(f"  Probable:  {len([f for f in unified_findings if f.verification_status == 'probable'])}")
        log(f"  Possible:  {len([f for f in unified_findings if f.verification_status == 'possible'])}")
        log(f"Report: {report_path}")
        log(f"Database: {self.ja_db_path}")
        log("=" * 60)

        return unified_findings


# ============================================================
# Helpers
# ============================================================

def _load_findings_from_db(db_path: Path) -> list:
    """Load unified_findings from SQLite into UnifiedFinding objects."""
    if not db_path.exists():
        log(f"Database not found: {db_path}", "ERROR")
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM unified_findings ORDER BY overall_confidence DESC").fetchall()
    conn.close()
    findings = []
    for r in rows:
        findings.append(UnifiedFinding(
            uf_id=r["uf_id"],
            vuln_type=r["vuln_type"],
            severity=r["severity"],
            cwe_id=r["cwe_id"] or "",
            title=r["title"],
            description=r["description"] or "",
            class_name=r["class_name"] or "",
            method_name=r["method_name"] or "",
            method_desc=r["method_desc"] or "",
            source_file=r["source_file"] or "",
            line_number=r["line_number"] or 0,
            codeql_cf_id=r["codeql_cf_id"] or 0,
            codeql_confidence=r["codeql_confidence"] or 0.0,
            codeql_taint_path=r["codeql_taint_path"] or "",
            ja_cc_id=r["ja_cc_id"] or 0,
            ja_entry_path=r["ja_entry_path"] or "",
            ja_call_chain=r["ja_call_chain"] or "[]",
            ja_reachable=r["ja_reachable"] or 0,
            ja_spring_route=r["ja_spring_route"] or "",
            overall_confidence=r["overall_confidence"] or 0.0,
            verification_status=r["verification_status"],
            exploit_hint=r["exploit_hint"] or "",
            code_snippet=r["code_snippet"] or "",
            poc_template=r["poc_template"] or "",
            evidence_hash=r["evidence_hash"] or "",
        ))
    return findings


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Unified Security Audit Engine")
    sub = parser.add_subparsers(dest="command")

    # Full pipeline
    p_run = sub.add_parser("run", help="Run full audit pipeline")
    p_run.add_argument("--jar", "-j", required=True, help="Target JAR/WAR file")
    p_run.add_argument("--work-dir", "-d", help="Working directory")
    p_run.add_argument("--skip-codeql", action="store_true", help="Skip CodeQL analysis")

    # Phase 1 only
    p_collect = sub.add_parser("collect", help="Phase 1: Data collection only")
    p_collect.add_argument("--jar", "-j", required=True, help="Target JAR/WAR file")
    p_collect.add_argument("--work-dir", "-d", required=True, help="Working directory")

    # Phase 2a only (CodeQL)
    p_codeql = sub.add_parser("codeql", help="Phase 2a: CodeQL analysis only")
    p_codeql.add_argument("--work-dir", "-d", required=True, help="Working directory")

    # Phase 2b only (JA scan)
    p_scan = sub.add_parser("scan", help="Phase 2b: jar-analyzer sink scan")
    p_scan.add_argument("--db", required=True, help="jar-analyzer.db path")
    p_scan.add_argument("--jar", "-j", required=True, help="Target JAR file")

    # Phase 3 only
    p_correlate = sub.add_parser("correlate", help="Phase 3: Correlation only")
    p_correlate.add_argument("--work-dir", "-d", required=True, help="Working directory")

    # Report
    p_report = sub.add_parser("report", help="Generate report from existing data")
    p_report.add_argument("--work-dir", "-d", required=True, help="Working directory")
    p_report.add_argument("--jar", "-j", required=True, help="Target JAR file")

    args = parser.parse_args()

    if args.command == "run":
        pipeline = UnifiedAuditPipeline(args.jar, args.work_dir, args.skip_codeql)
        pipeline.run()
    elif args.command == "collect":
        collector = DataCollector(args.jar, args.work_dir,
                                   str(Path(args.work_dir) / "jar-analyzer.db"))
        collector.run()
    elif args.command == "codeql":
        decompiled = Path(args.work_dir) / "decompiled"
        codeql = CodeQLAnalyzer(args.work_dir, str(decompiled))
        findings = codeql.run()
        print(json.dumps([asdict(f) for f in findings], indent=2, default=str))
    elif args.command == "scan":
        with JAScanner(args.db, args.jar) as scanner:
            sinks = scanner.find_sinks()
            routes = scanner.get_spring_routes()
            gaps = scanner.find_auth_gaps()
            print(json.dumps({
                "sinks": sinks,
                "routes": routes,
                "auth_gaps": gaps,
            }, indent=2, default=str))
    elif args.command == "report":
        findings = _load_findings_from_db(Path(args.work_dir) / "jar-analyzer.db")
        reporter = ReportGenerator(args.work_dir, args.jar)
        reporter.generate(findings)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
