"""
MCP Security Audit Module

Provides programmatic interface for auditing MCP server security.
Used by both CLI script and admin panel.
"""

from typing import Optional, Dict, Any, List, Tuple
import httpx


class MCPSecurityAuditor:
    """Audits MCP server security"""
    
    def __init__(self, url: str, bearer_token: Optional[str] = None):
        self.url = url
        self.bearer_token = bearer_token
        self.results: List[Tuple[str, str, str]] = []  # (status, test_name, message)
        
    def mcp_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0
    ) -> Tuple[int, Optional[Dict]]:
        """Make MCP JSON-RPC request"""
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if headers:
            request_headers.update(headers)
            
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method
        }
        if params:
            payload["params"] = params
            
        try:
            response = httpx.post(
                self.url,
                json=payload,
                headers=request_headers,
                timeout=timeout,
                follow_redirects=True
            )
            
            try:
                data = response.json()
            except:
                data = None
                
            return response.status_code, data
        except httpx.RequestError as e:
            return 0, {"error": str(e)}
            
    def test_unauthenticated_access(self) -> Dict[str, Any]:
        """Test 1: Check if MCP endpoint is open without authentication"""
        test_name = "Unauthenticated Access"
        
        status, data = self.mcp_request("tools/list")
        
        if status == 0:
            result = {
                "status": "error",
                "name": test_name,
                "message": "Server unreachable",
                "details": data
            }
        elif status == 401 or status == 403:
            result = {
                "status": "pass",
                "name": test_name,
                "message": f"Server requires authentication ({status})",
                "details": None
            }
        elif status == 200:
            tools_count = 0
            if data and "result" in data:
                tools = data.get("result", {}).get("tools", [])
                tools_count = len(tools)
            result = {
                "status": "fail",
                "name": test_name,
                "message": f"🚨 Server allows unauthenticated access! ({tools_count} tools exposed)",
                "details": data
            }
        else:
            result = {
                "status": "warn",
                "name": test_name,
                "message": f"Unexpected status code: {status}",
                "details": data
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
            
    def test_invalid_token(self) -> Dict[str, Any]:
        """Test 2: Check if invalid tokens are rejected"""
        test_name = "Invalid Token Rejection"
        
        fake_token = "fake_invalid_token_12345"
        headers = {"Authorization": f"Bearer {fake_token}"}
        
        status, data = self.mcp_request("tools/list", headers=headers)
        
        if status == 401 or status == 403:
            result = {
                "status": "pass",
                "name": test_name,
                "message": "Server rejects invalid tokens",
                "details": None
            }
        elif status == 200:
            result = {
                "status": "fail",
                "name": test_name,
                "message": "🚨 Server accepts invalid tokens!",
                "details": data
            }
        else:
            result = {
                "status": "warn",
                "name": test_name,
                "message": f"Unexpected status code: {status}",
                "details": data
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
            
    def test_valid_token(self) -> Dict[str, Any]:
        """Test 3: Test with provided bearer token (if any)"""
        test_name = "Provided Token Access"
        
        if not self.bearer_token:
            result = {
                "status": "skip",
                "name": test_name,
                "message": "⊘ No token provided - skipped",
                "details": None
            }
            self.results.append(("skip", test_name, result["message"]))
            return result
            
        # Token provided - test if it works
        headers = {"Authorization": f"Bearer {self.bearer_token}"}
        status, data = self.mcp_request("tools/list", headers=headers)
        
        if status == 200:
            tools_count = 0
            if data and "result" in data:
                tools = data.get("result", {}).get("tools", [])
                tools_count = len(tools)
            result = {
                "status": "pass",
                "name": test_name,
                "message": f"✅ Token works - {tools_count} tools accessible",
                "details": data
            }
        elif status == 401 or status == 403:
            result = {
                "status": "fail",
                "name": test_name,
                "message": "⚠️ Token rejected (check if valid)",
                "details": data
            }
        else:
            result = {
                "status": "warn",
                "name": test_name,
                "message": f"Unexpected status code: {status}",
                "details": data
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
            
    def test_tools_call_unauthorized(self) -> Dict[str, Any]:
        """Test 4: Try to call a tool without authorization"""
        test_name = "Unauthorized Tool Execution"
        
        status, data = self.mcp_request(
            "tools/call",
            params={"name": "test_tool", "arguments": {}}
        )
        
        if status == 401 or status == 403:
            result = {
                "status": "pass",
                "name": test_name,
                "message": "Tool execution requires authentication",
                "details": None
            }
        elif status == 200:
            result = {
                "status": "fail",
                "name": test_name,
                "message": "🚨 Can execute tools without auth!",
                "details": data
            }
        elif status == 404 or status == 400:
            result = {
                "status": "warn",
                "name": test_name,
                "message": "Tool not found (endpoint might be open)",
                "details": data
            }
        else:
            result = {
                "status": "info",
                "name": test_name,
                "message": f"Status: {status}",
                "details": data
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
            
    def test_initialize_unauthorized(self) -> Dict[str, Any]:
        """Test 5: Check initialize method without auth"""
        test_name = "Unauthorized Initialize"
        
        status, data = self.mcp_request(
            "initialize",
            params={"protocolVersion": "2024-11-05", "clientInfo": {"name": "test", "version": "1.0"}}
        )
        
        if status == 401 or status == 403:
            result = {
                "status": "pass",
                "name": test_name,
                "message": "Initialize requires authentication",
                "details": None
            }
        elif status == 200:
            result = {
                "status": "warn",
                "name": test_name,
                "message": "Initialize method is open (may be intentional)",
                "details": data
            }
        else:
            result = {
                "status": "info",
                "name": test_name,
                "message": f"Status: {status}",
                "details": data
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
            
    def test_error_disclosure(self) -> Dict[str, Any]:
        """Test 6: Check for information disclosure in errors"""
        test_name = "Error Information Disclosure"
        
        status, data = self.mcp_request("invalid_method_xyz")
        
        if data and isinstance(data, dict):
            error_msg = str(data)
            
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
                result = {
                    "status": "warn",
                    "name": test_name,
                    "message": f"Error messages may disclose: {', '.join(set(disclosed))}",
                    "details": data
                }
            else:
                result = {
                    "status": "pass",
                    "name": test_name,
                    "message": "No obvious information disclosure",
                    "details": None
                }
        else:
            result = {
                "status": "info",
                "name": test_name,
                "message": "Could not analyze error responses",
                "details": None
            }
            
        self.results.append((result["status"], test_name, result["message"]))
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests and return summary"""
        self.results = []
        
        test_results = [
            self.test_unauthenticated_access(),
            self.test_invalid_token(),
            self.test_valid_token(),
            self.test_tools_call_unauthorized(),
            self.test_initialize_unauthorized(),
            self.test_error_disclosure(),
        ]
        
        # Calculate summary
        total = len([r for r in test_results if r["status"] != "skip"])
        passed = sum(1 for r in test_results if r["status"] == "pass")
        failed = sum(1 for r in test_results if r["status"] == "fail")
        warned = sum(1 for r in test_results if r["status"] == "warn")
        skipped = sum(1 for r in test_results if r["status"] == "skip")
        
        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "warned": warned,
            "skipped": skipped,
            "severity": "critical" if failed > 0 else ("warning" if warned > 0 else "success")
        }
        
        return {
            "url": self.url,
            "tests": test_results,
            "summary": summary
        }
    
    def export_json(self) -> Dict[str, Any]:
        """Export test results as JSON with metadata"""
        import datetime
        
        # Run all tests to get fresh results
        results = self.run_all_tests()
        
        # Add metadata
        export_data = {
            "metadata": {
                "tool": "AuthMCP Gateway - MCP Security Audit",
                "version": "1.0.1",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tested_url": self.url,
                "has_token": bool(self.bearer_token)
            },
            "summary": results["summary"],
            "tests": results["tests"]
        }
        
        return export_data

