#!/usr/bin/env python3
"""
Simplified HTTP Conformance Test Runner
Based on the CISPA HTTP Conformance project, adapted for local server testing
"""

import sys
import time
import httpx
from typing import Dict, List, Tuple

# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


class ConformanceTest:
    """Basic HTTP/1.1 conformance tests"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client(follow_redirects=False, timeout=10.0)
        self.results = []

    def test_basic_get(self) -> Tuple[bool, str]:
        """Test basic GET request"""
        try:
            response = self.client.get(f"{self.base_url}/")
            return response.status_code == 200, f"Status: {response.status_code}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_http_version(self) -> Tuple[bool, str]:
        """Test HTTP/1.1 version in response"""
        try:
            response = self.client.get(f"{self.base_url}/")
            version = f"HTTP/{response.http_version}"
            is_http11 = response.http_version == "HTTP/1.1"
            return is_http11, f"Version: {version}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_content_length_header(self) -> Tuple[bool, str]:
        """Test Content-Length header presence"""
        try:
            response = self.client.get(f"{self.base_url}/content-length")
            has_cl = 'content-length' in response.headers
            cl_value = response.headers.get('content-length', 'N/A')
            body_len = len(response.content)

            if has_cl:
                matches = int(cl_value) == body_len
                return matches, f"Content-Length: {cl_value}, Body: {body_len}"
            return False, "Content-Length header missing"
        except Exception as e:
            return False, f"Error: {e}"

    def test_redirect_status(self) -> Tuple[bool, str]:
        """Test 3xx redirect status codes"""
        try:
            response = self.client.get(f"{self.base_url}/status/301")
            is_redirect = 300 <= response.status_code < 400
            has_location = 'location' in response.headers
            return is_redirect and has_location, f"Status: {response.status_code}, Location: {response.headers.get('location', 'N/A')}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_4xx_status(self) -> Tuple[bool, str]:
        """Test 4xx client error status codes"""
        try:
            response = self.client.get(f"{self.base_url}/status/404")
            is_4xx = 400 <= response.status_code < 500
            return is_4xx, f"Status: {response.status_code}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_5xx_status(self) -> Tuple[bool, str]:
        """Test 5xx server error status codes"""
        try:
            response = self.client.get(f"{self.base_url}/status/500")
            is_5xx = 500 <= response.status_code < 600
            return is_5xx, f"Status: {response.status_code}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_method_post(self) -> Tuple[bool, str]:
        """Test POST method support"""
        try:
            response = self.client.post(f"{self.base_url}/methods", content="test data")
            return response.status_code in [200, 201, 204], f"Status: {response.status_code}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_method_options(self) -> Tuple[bool, str]:
        """Test OPTIONS method support"""
        try:
            response = self.client.request("OPTIONS", f"{self.base_url}/methods")
            has_allow = 'allow' in response.headers
            return response.status_code == 200 and has_allow, f"Status: {response.status_code}, Allow: {response.headers.get('allow', 'N/A')}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_connection_close(self) -> Tuple[bool, str]:
        """Test Connection: close header handling"""
        try:
            response = self.client.get(f"{self.base_url}/close")
            connection = response.headers.get('connection', '').lower()
            return 'close' in connection, f"Connection: {connection}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_custom_headers(self) -> Tuple[bool, str]:
        """Test custom header support"""
        try:
            response = self.client.get(f"{self.base_url}/headers")
            has_custom = 'x-custom-header' in response.headers
            return has_custom, f"Custom header: {response.headers.get('x-custom-header', 'N/A')}"
        except Exception as e:
            return False, f"Error: {e}"

    def test_large_response(self) -> Tuple[bool, str]:
        """Test handling of large responses"""
        try:
            response = self.client.get(f"{self.base_url}/large")
            body_len = len(response.content)
            return body_len > 1000, f"Response size: {body_len} bytes"
        except Exception as e:
            return False, f"Error: {e}"

    def run_all_tests(self) -> Dict:
        """Run all conformance tests"""
        tests = [
            ("Basic GET Request", self.test_basic_get),
            ("HTTP/1.1 Version", self.test_http_version),
            ("Content-Length Header", self.test_content_length_header),
            ("Redirect Status (3xx)", self.test_redirect_status),
            ("Client Error Status (4xx)", self.test_4xx_status),
            ("Server Error Status (5xx)", self.test_5xx_status),
            ("POST Method", self.test_method_post),
            ("OPTIONS Method", self.test_method_options),
            ("Connection Close", self.test_connection_close),
            ("Custom Headers", self.test_custom_headers),
            ("Large Response", self.test_large_response),
        ]

        print(f"\n{BLUE}Running HTTP/1.1 Conformance Tests{RESET}")
        print("=" * 70)

        passed = 0
        failed = 0

        for test_name, test_func in tests:
            try:
                success, details = test_func()
                status = f"{GREEN}PASS{RESET}" if success else f"{RED}FAIL{RESET}"
                print(f"{status} | {test_name:30s} | {details}")

                if success:
                    passed += 1
                else:
                    failed += 1

                self.results.append({
                    'test': test_name,
                    'passed': success,
                    'details': details
                })
            except Exception as e:
                print(f"{RED}ERROR{RESET} | {test_name:30s} | {e}")
                failed += 1
                self.results.append({
                    'test': test_name,
                    'passed': False,
                    'details': str(e)
                })

        print("=" * 70)
        total = passed + failed
        percentage = (passed / total * 100) if total > 0 else 0

        color = GREEN if percentage >= 80 else YELLOW if percentage >= 60 else RED
        print(f"\n{color}Results: {passed}/{total} tests passed ({percentage:.1f}%){RESET}")

        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'percentage': percentage,
            'results': self.results
        }


def main():
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://127.0.0.1:8080"

    print(f"{BLUE}[INFO] Testing server at: {base_url}{RESET}")

    # Wait for server to be ready
    print(f"{BLUE}[INFO] Checking if server is available...{RESET}")
    client = httpx.Client(timeout=5.0)

    for i in range(10):
        try:
            response = client.get(base_url)
            print(f"{GREEN}[INFO] Server is ready!{RESET}")
            break
        except Exception:
            if i < 9:
                time.sleep(1)
            else:
                print(f"{RED}[ERROR] Server is not responding at {base_url}{RESET}")
                sys.exit(1)

    client.close()

    # Run tests
    tester = ConformanceTest(base_url)
    results = tester.run_all_tests()
    tester.client.close()

    # Exit with appropriate code
    sys.exit(0 if results['failed'] == 0 else 1)


if __name__ == "__main__":
    main()
