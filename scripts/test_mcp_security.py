#!/usr/bin/env python3
"""
MCP Security Testing Script

Tests MCP servers for common security issues:
- Open endpoints (no authentication)
- Weak authentication
- Information disclosure
- Exposed tools without authorization

Usage:
    python test_mcp_security.py http://localhost:8000/mcp
    python test_mcp_security.py https://mcp.example.com/mcp --bearer TOKEN
"""

import argparse
import sys
from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:
    print("❌ Error: httpx not installed")
    print("Install: pip install httpx")
    sys.exit(1)


class Colors:
    """ANSI colors for terminal output"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


class MCPSecurityTester:
    """Tests MCP server security"""

    def __init__(self, url: str, bearer_token: Optional[str] = None):
        self.url = url
        self.bearer_token = bearer_token
        self.results = []

    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}\n")

    def print_test(self, name: str):
        """Print test name"""
        print(f"{Colors.BOLD}🔍 Test: {name}{Colors.END}")

    def print_pass(self, message: str):
        """Print success message"""
        print(f"  {Colors.GREEN}✅ PASS:{Colors.END} {message}")
        self.results.append(("PASS", message))

    def print_fail(self, message: str):
        """Print failure message"""
        print(f"  {Colors.RED}❌ FAIL:{Colors.END} {message}")
        self.results.append(("FAIL", message))

    def print_warn(self, message: str):
        """Print warning message"""
        print(f"  {Colors.YELLOW}⚠️  WARN:{Colors.END} {message}")
        self.results.append(("WARN", message))

    def print_info(self, message: str):
        """Print info message"""
        print(f"  {Colors.BLUE}ℹ️  INFO:{Colors.END} {message}")

    def mcp_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> tuple[int, Optional[Dict]]:
        """Make MCP JSON-RPC request"""
        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        payload = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params:
            payload["params"] = params

        try:
            response = httpx.post(
                self.url, json=payload, headers=request_headers, timeout=10.0, follow_redirects=True
            )

            try:
                data = response.json()
            except:
                data = None

            return response.status_code, data
        except httpx.RequestError as e:
            print(f"  {Colors.RED}❌ Request failed: {e}{Colors.END}")
            return 0, None

    def test_unauthenticated_access(self):
        """Test 1: Check if MCP endpoint is open without authentication"""
        self.print_test("Unauthenticated Access to tools/list")

        status, data = self.mcp_request("tools/list")

        if status == 0:
            self.print_fail("Server unreachable")
            return

        if status == 401:
            self.print_pass("Server requires authentication (401)")
        elif status == 403:
            self.print_pass("Server denies access (403)")
        elif status == 200:
            self.print_fail("🚨 SECURITY ISSUE: Server allows unauthenticated access!")
            if data and "result" in data:
                tools = data.get("result", {}).get("tools", [])
                self.print_warn(f"Exposed {len(tools)} tools without authentication:")
                for tool in tools[:5]:  # Show first 5
                    self.print_info(f"  - {tool.get('name', 'unknown')}")
                if len(tools) > 5:
                    self.print_info(f"  ... and {len(tools) - 5} more")
        else:
            self.print_warn(f"Unexpected status code: {status}")

    def test_invalid_token(self):
        """Test 2: Check if invalid tokens are rejected"""
        self.print_test("Invalid Token Rejection")

        fake_token = "fake_invalid_token_12345"
        headers = {"Authorization": f"Bearer {fake_token}"}

        status, data = self.mcp_request("tools/list", headers=headers)

        if status == 401 or status == 403:
            self.print_pass("Server rejects invalid tokens")
        elif status == 200:
            self.print_fail("🚨 SECURITY ISSUE: Server accepts invalid tokens!")
        else:
            self.print_warn(f"Unexpected status code: {status}")

    def test_valid_token(self):
        """Test 3: Test with valid bearer token (if provided)"""
        if not self.bearer_token:
            self.print_test("Valid Token Access (SKIPPED - no token provided)")
            self.print_info("Use --bearer TOKEN to test with valid token")
            return

        self.print_test("Valid Token Access")

        headers = {"Authorization": f"Bearer {self.bearer_token}"}
        status, data = self.mcp_request("tools/list", headers=headers)

        if status == 200:
            if data and "result" in data:
                tools = data.get("result", {}).get("tools", [])
                self.print_pass(f"Authenticated access successful ({len(tools)} tools)")
                self.print_info(
                    f"Available tools: {', '.join([t.get('name', '?') for t in tools[:3]])}"
                )
            else:
                self.print_pass("Authenticated access successful")
        elif status == 401 or status == 403:
            self.print_fail("Valid token was rejected (check if token is still valid)")
        else:
            self.print_warn(f"Unexpected status code: {status}")

    def test_tools_call_unauthorized(self):
        """Test 4: Try to call a tool without authorization"""
        self.print_test("Unauthorized Tool Execution")

        status, data = self.mcp_request("tools/call", params={"name": "test_tool", "arguments": {}})

        if status == 401 or status == 403:
            self.print_pass("Tool execution requires authentication")
        elif status == 200:
            self.print_fail("🚨 SECURITY ISSUE: Can execute tools without auth!")
        elif status == 404 or status == 400:
            self.print_warn("Tool not found (but endpoint might be open)")
        else:
            self.print_warn(f"Unexpected status code: {status}")

    def test_initialize_unauthorized(self):
        """Test 5: Check initialize method without auth"""
        self.print_test("Unauthorized initialize")

        status, data = self.mcp_request(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        )

        if status == 401 or status == 403:
            self.print_pass("Initialize requires authentication")
        elif status == 200:
            self.print_warn("Initialize method is open (may be intentional)")
        else:
            self.print_info(f"Status: {status}")

    def test_error_disclosure(self):
        """Test 6: Check for information disclosure in errors"""
        self.print_test("Error Information Disclosure")

        # Try invalid JSON-RPC
        status, data = self.mcp_request("invalid_method_xyz")

        if data and isinstance(data, dict):
            error_msg = str(data)

            # Check for sensitive info in errors
            sensitive_patterns = [
                ("/home/", "file paths"),
                ("/usr/", "file paths"),
                ("C:\\", "file paths"),
                ("Exception:", "stack traces"),
                ("Traceback", "stack traces"),
                ("at line", "line numbers"),
            ]

            disclosed = []
            for pattern, description in sensitive_patterns:
                if pattern in error_msg:
                    disclosed.append(description)

            if disclosed:
                self.print_warn(f"Error messages may disclose: {', '.join(set(disclosed))}")
            else:
                self.print_pass("No obvious information disclosure in errors")
        else:
            self.print_info("Could not analyze error responses")

    def print_summary(self):
        """Print test summary"""
        self.print_header("SUMMARY")

        total = len(self.results)
        passed = sum(1 for r in self.results if r[0] == "PASS")
        failed = sum(1 for r in self.results if r[0] == "FAIL")
        warned = sum(1 for r in self.results if r[0] == "WARN")

        print(f"Total Tests: {total}")
        print(f"{Colors.GREEN}Passed: {passed}{Colors.END}")
        print(f"{Colors.RED}Failed: {failed}{Colors.END}")
        print(f"{Colors.YELLOW}Warnings: {warned}{Colors.END}\n")

        if failed > 0:
            print(f"{Colors.RED}{Colors.BOLD}⚠️  SECURITY ISSUES DETECTED!{Colors.END}")
            print(f"{Colors.RED}Review failed tests above and fix issues.{Colors.END}\n")
            return 1
        elif warned > 0:
            print(f"{Colors.YELLOW}⚠️  Some warnings detected. Review recommended.{Colors.END}\n")
            return 0
        else:
            print(f"{Colors.GREEN}✅ All tests passed! Server appears secure.{Colors.END}\n")
            return 0

    def test_specific_server_endpoint(self):
        """Test 7: Check if named server endpoints require auth"""
        self.print_test("Named Server Endpoint Security")

        # Try common MCP server endpoint patterns
        test_paths = ["/github-mcp", "/rag-server", "/code-server"]

        for path in test_paths:
            url = self.url.rsplit("/", 1)[0] + path
            try:
                response = httpx.post(
                    url,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Content-Type": "application/json"},
                    timeout=5.0,
                    follow_redirects=False,
                )

                if response.status_code in [401, 403]:
                    self.print_pass(f"Named endpoint {path} requires auth")
                    break  # At least one works
                elif response.status_code == 404:
                    continue  # Endpoint doesn't exist
                elif response.status_code == 200:
                    self.print_fail(f"🚨 Named endpoint {path} is open!")
                    break
            except:
                continue
        else:
            self.print_info("No named server endpoints found (tested common patterns)")

    def run_all_tests(self):
        """Run all security tests"""
        self.print_header(f"MCP Security Testing")
        print(f"Target: {self.url}\n")

        self.test_unauthenticated_access()
        self.test_invalid_token()
        self.test_valid_token()
        self.test_tools_call_unauthorized()
        self.test_initialize_unauthorized()
        self.test_specific_server_endpoint()
        self.test_error_disclosure()

        return self.print_summary()


def main():
    parser = argparse.ArgumentParser(
        description="Test MCP server security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test local development server
  python test_mcp_security.py http://localhost:8000/mcp
  
  # Test production server with authentication
  python test_mcp_security.py https://mcp.example.com/mcp --bearer YOUR_TOKEN
  
  # Test AuthMCP Gateway
  python test_mcp_security.py http://localhost:9105/mcp
        """,
    )

    parser.add_argument("url", help="MCP endpoint URL (e.g., http://localhost:8000/mcp)")

    parser.add_argument(
        "--bearer", "-b", help="Bearer token for authenticated tests", metavar="TOKEN"
    )

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(("http://", "https://")):
        print(f"{Colors.RED}Error: URL must start with http:// or https://{Colors.END}")
        sys.exit(1)

    # Run tests
    tester = MCPSecurityTester(args.url, args.bearer)
    exit_code = tester.run_all_tests()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
