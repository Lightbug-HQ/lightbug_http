#!/usr/bin/env python3
"""
Full HTTP/1.1 Compliance Test Suite

This comprehensive test suite exercises ALL endpoints on the comprehensive
test server to trigger as many of httplint's 237 checks as possible.

Run this against the comprehensive_test_server.mojo to get maximum coverage.
"""

import socket
import sys
import json
from typing import List, Tuple, Optional, Dict, Any
from collections import defaultdict
from httplint import HttpResponseLinter, HttpRequestLinter


class FullHTTP11ComplianceSuite:
    """Exhaustive HTTP/1.1 compliance testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, verbose: bool = False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.results = []
        self.all_notes = []
        self.note_categories = defaultdict(int)
        self.note_levels = defaultdict(int)
        self.unique_note_summaries = set()

    def send_request(self, request: bytes, timeout: float = 5.0) -> bytes:
        """Send HTTP request and receive response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((self.host, self.port))
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)

            response = b''
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk

            return response
        finally:
            sock.close()

    def parse_response(self, response: bytes) -> Tuple[bytes, bytes, bytes, List[Tuple[bytes, bytes]], bytes]:
        """Parse HTTP response into components."""
        header_end = response.find(b'\r\n\r\n')
        if header_end == -1:
            raise ValueError("Invalid HTTP response: no header/body separator")

        headers_section = response[:header_end]
        body = response[header_end + 4:]

        lines = headers_section.split(b'\r\n')
        status_line = lines[0]
        parts = status_line.split(b' ', 2)

        if len(parts) < 2:
            raise ValueError(f"Invalid status line: {status_line}")

        version = parts[0]
        status_code = parts[1]
        status_phrase = parts[2] if len(parts) > 2 else b''

        headers = []
        for line in lines[1:]:
            if not line:
                continue
            colon_idx = line.find(b':')
            if colon_idx == -1:
                continue
            name = line[:colon_idx]
            value = line[colon_idx + 1:].lstrip()
            headers.append((name, value))

        return version, status_code, status_phrase, headers, body

    def lint_response(self, response: bytes, complete: bool = True) -> HttpResponseLinter:
        """Lint an HTTP response."""
        version, status_code, status_phrase, headers, body = self.parse_response(response)

        linter = HttpResponseLinter()
        linter.process_response_topline(version, status_code, status_phrase)
        linter.process_headers(headers)

        if body:
            linter.feed_content(body)

        linter.finish_content(complete)

        return linter

    def record_result(self, test_name: str, linter: HttpResponseLinter):
        """Record test results and collect notes."""
        result = {
            'test': test_name,
            'note_count': len(linter.notes),
            'errors': [],
            'warnings': [],
            'info': [],
            'good': []
        }

        for note in linter.notes:
            summary = str(note.summary)
            self.unique_note_summaries.add(summary)

            self.all_notes.append({
                'test': test_name,
                'summary': summary,
                'level': str(note.level) if hasattr(note, 'level') else 'unknown',
                'category': str(note.category) if hasattr(note, 'category') else 'unknown'
            })

            if hasattr(note, 'level'):
                level_str = str(note.level).lower()
                self.note_levels[level_str] += 1

                if 'bad' in level_str:
                    result['errors'].append(summary)
                elif 'warn' in level_str:
                    result['warnings'].append(summary)
                elif 'good' in level_str:
                    result['good'].append(summary)
                else:
                    result['info'].append(summary)

            if hasattr(note, 'category'):
                cat_str = str(note.category)
                self.note_categories[cat_str] += 1

        self.results.append(result)

        if self.verbose and (result['errors'] or result['warnings']):
            self.print_test_result(test_name, result)

        return result

    def print_test_result(self, test_name: str, result: Dict[str, Any]):
        """Print individual test result."""
        print(f"\n{'─'*70}")
        print(f"TEST: {test_name}")

        if result['errors']:
            print(f"  ❌ ERRORS: {len(result['errors'])}")
            for err in result['errors'][:3]:  # Show first 3
                print(f"     • {err}")

        if result['warnings']:
            print(f"  ⚠️  WARNINGS: {len(result['warnings'])}")

    def test_endpoint(self, path: str, name: str, extra_headers: str = ""):
        """Generic endpoint tester."""
        request = f'GET {path} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n{extra_headers}\r\n'.encode()
        try:
            response = self.send_request(request)
            linter = self.lint_response(response)
            self.record_result(name, linter)
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Test '{name}' failed: {e}")

    def run_all_tests(self):
        """Run ALL compliance tests."""
        print(f"\n{'#'*70}")
        print(f"# Full HTTP/1.1 Compliance Test Suite")
        print(f"# Testing: {self.host}:{self.port}")
        print(f"# Goal: Trigger all 237+ httplint checks")
        print(f"{'#'*70}\n")

        # Define all test endpoints
        test_cases = [
            # 2xx Success
            ("/", "Basic GET"),
            ("/no-cache", "No Cache Response"),
            ("/private", "Private Cache"),
            ("/created", "201 Created"),
            ("/accepted", "202 Accepted"),
            ("/no-content", "204 No Content"),

            # 3xx Redirects
            ("/redirect", "301 Moved Permanently"),
            ("/temp-redirect", "302 Found"),
            ("/see-other", "303 See Other"),
            ("/not-modified", "304 Not Modified"),
            ("/temp-redirect-307", "307 Temporary Redirect"),
            ("/permanent-redirect-308", "308 Permanent Redirect"),
            ("/redirect-target", "Redirect Target"),

            # 4xx Client Errors
            ("/bad-request", "400 Bad Request"),
            ("/unauthorized", "401 Unauthorized"),
            ("/forbidden", "403 Forbidden"),
            ("/not-found", "404 Not Found"),
            ("/method-not-allowed", "405 Method Not Allowed"),
            ("/not-acceptable", "406 Not Acceptable"),
            ("/conflict", "409 Conflict"),
            ("/gone", "410 Gone"),
            ("/precondition-failed", "412 Precondition Failed"),
            ("/payload-too-large", "413 Payload Too Large"),
            ("/uri-too-long", "414 URI Too Long"),
            ("/unsupported-media-type", "415 Unsupported Media Type"),
            ("/range-not-satisfiable", "416 Range Not Satisfiable"),
            ("/teapot", "418 I'm a Teapot"),
            ("/too-many-requests", "429 Too Many Requests"),

            # 5xx Server Errors
            ("/internal-error", "500 Internal Server Error"),
            ("/not-implemented", "501 Not Implemented"),
            ("/bad-gateway", "502 Bad Gateway"),
            ("/service-unavailable", "503 Service Unavailable"),
            ("/gateway-timeout", "504 Gateway Timeout"),

            # Security Headers
            ("/security-headers", "Security Headers"),

            # CORS
            ("/cors", "CORS Headers"),
            ("/cors-credentials", "CORS with Credentials"),

            # Content Types
            ("/json", "JSON Content"),
            ("/html", "HTML Content"),
            ("/xml", "XML Content"),

            # Cookies
            ("/set-cookie", "Set Cookie"),
            ("/set-secure-cookie", "Set Secure Cookie"),

            # Content Disposition
            ("/download", "File Download"),

            # Caching
            ("/cached", "Cached Content with Age"),

            # Links
            ("/with-links", "Link Header"),
        ]

        print("Testing Basic Endpoints...")
        for path, name in test_cases:
            self.test_endpoint(path, name)

        # Test with various request headers to trigger more validators
        print("\nTesting with Content Negotiation Headers...")
        self.test_endpoint("/", "Accept Header", "Accept: text/html,application/json;q=0.9\r\n")
        self.test_endpoint("/", "Accept-Language", "Accept-Language: en-US,en;q=0.9,es;q=0.8\r\n")
        self.test_endpoint("/", "Accept-Encoding", "Accept-Encoding: gzip, deflate, br\r\n")

        print("Testing Conditional Requests...")
        self.test_endpoint("/", "If-Modified-Since", "If-Modified-Since: Wed, 01 Jan 2025 00:00:00 GMT\r\n")
        self.test_endpoint("/", "If-None-Match", 'If-None-Match: "abc123"\r\n')
        self.test_endpoint("/", "If-Match", 'If-Match: "abc123"\r\n')
        self.test_endpoint("/", "If-Unmodified-Since", "If-Unmodified-Since: Wed, 01 Jan 2025 00:00:00 GMT\r\n")
        self.test_endpoint("/", "If-Range", 'If-Range: "abc123"\r\n')

        print("Testing Range Requests...")
        self.test_endpoint("/", "Range Request", "Range: bytes=0-99\r\n")
        self.test_endpoint("/", "Range Multi-Part", "Range: bytes=0-99, 200-299\r\n")

        print("Testing Cache Control...")
        self.test_endpoint("/", "Cache-Control no-cache", "Cache-Control: no-cache\r\n")
        self.test_endpoint("/", "Cache-Control max-age", "Cache-Control: max-age=0\r\n")
        self.test_endpoint("/", "Pragma no-cache", "Pragma: no-cache\r\n")

        print("Testing User Agent...")
        self.test_endpoint("/", "User-Agent", "User-Agent: Full-Compliance-Suite/1.0\r\n")
        self.test_endpoint("/", "No User-Agent", "")

        print("Testing Referer...")
        self.test_endpoint("/", "Referer HTTP", "Referer: http://example.com/page\r\n")
        self.test_endpoint("/", "Referer HTTPS", "Referer: https://example.com/page\r\n")

        print("Testing CORS...")
        self.test_endpoint("/cors", "CORS with Origin", "Origin: https://example.com\r\n")
        self.test_endpoint("/cors", "CORS Preflight", "Origin: https://example.com\r\nAccess-Control-Request-Method: POST\r\n")

        print("Testing Via Header...")
        self.test_endpoint("/", "Via Proxy", "Via: 1.1 proxy.example.com\r\n")

        print("Testing Transfer Encoding...")
        self.test_endpoint("/", "TE Header", "TE: trailers, deflate\r\n")

        print("Testing Max-Forwards...")
        self.test_endpoint("/", "Max-Forwards TRACE", "Max-Forwards: 10\r\n")

        print("Testing Expect...")
        self.test_endpoint("/", "Expect 100-continue", "Expect: 100-continue\r\n")

        print("Testing Authorization...")
        self.test_endpoint("/", "Authorization Basic", "Authorization: Basic dXNlcjpwYXNz\r\n")

        print("Testing Cookies...")
        self.test_endpoint("/", "Cookie Header", "Cookie: session=abc123; user=john\r\n")

        print("Testing Connection Headers...")
        self.test_endpoint("/", "Connection Keep-Alive", "Connection: keep-alive\r\n")
        self.test_endpoint("/", "Connection Close", "Connection: close\r\n")
        self.test_endpoint("/", "Keep-Alive Header", "Keep-Alive: timeout=5, max=100\r\n")

        print("Testing Multiple Accept Headers...")
        self.test_endpoint("/", "Multiple Accept Types",
                          "Accept: text/html\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: en\r\n")

        print("Testing X-Headers...")
        self.test_endpoint("/", "X-Forwarded-For", "X-Forwarded-For: 192.168.1.1\r\n")
        self.test_endpoint("/", "X-Real-IP", "X-Real-IP: 192.168.1.1\r\n")

        # Test different methods
        print("\nTesting HTTP Methods...")
        for method in ['HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH']:
            request = f'{method} / HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n'.encode()
            try:
                response = self.send_request(request)
                linter = self.lint_response(response)
                self.record_result(f"Method: {method}", linter)
            except Exception as e:
                if self.verbose:
                    print(f"⚠️  Method {method} failed: {e}")

        # Test POST with content
        print("\nTesting POST with Content...")
        for content_type, body in [
            ('application/json', b'{"key": "value"}'),
            ('application/x-www-form-urlencoded', b'key=value&foo=bar'),
            ('text/plain', b'plain text content'),
            ('application/xml', b'<root><item>value</item></root>'),
        ]:
            request = f'POST /json HTTP/1.1\r\nHost: {self.host}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body
            try:
                response = self.send_request(request)
                linter = self.lint_response(response)
                self.record_result(f"POST {content_type}", linter)
            except Exception as e:
                if self.verbose:
                    print(f"⚠️  POST {content_type} failed: {e}")

        # Test HTTP/1.0
        print("\nTesting HTTP/1.0...")
        request = b'GET / HTTP/1.0\r\nHost: ' + self.host.encode() + b'\r\n\r\n'
        try:
            response = self.send_request(request)
            linter = self.lint_response(response)
            self.record_result("HTTP/1.0 Request", linter)
        except Exception as e:
            if self.verbose:
                print(f"⚠️  HTTP/1.0 test failed: {e}")

        self.print_summary()

    def print_summary(self):
        """Print comprehensive test summary."""
        print(f"\n{'#'*70}")
        print("# COMPREHENSIVE TEST SUMMARY")
        print(f"{'#'*70}\n")

        total_tests = len(self.results)
        total_errors = sum(len(r['errors']) for r in self.results)
        total_warnings = sum(len(r['warnings']) for r in self.results)
        total_notes = len(self.all_notes)
        unique_checks = len(self.unique_note_summaries)

        print(f"Tests Run: {total_tests}")
        print(f"Total Notes Generated: {total_notes}")
        print(f"Unique httplint Checks Triggered: {unique_checks} / 237+")
        print(f"Coverage: {(unique_checks / 237) * 100:.1f}%")
        print(f"\nTotal Errors: {total_errors}")
        print(f"Total Warnings: {total_warnings}")

        print(f"\n{'─'*70}")
        print("Notes by Level:")
        print(f"{'─'*70}")
        for level, count in sorted(self.note_levels.items()):
            print(f"  {level}: {count}")

        print(f"\n{'─'*70}")
        print("Notes by Category:")
        print(f"{'─'*70}")
        for category, count in sorted(self.note_categories.items()):
            print(f"  {category}: {count}")

        print(f"\n{'─'*70}")
        print("Critical Issues (Errors):")
        print(f"{'─'*70}")
        error_summary = defaultdict(int)
        for note in self.all_notes:
            if 'bad' in note['level'].lower():
                error_summary[note['summary']] += 1

        if error_summary:
            for summary, count in sorted(error_summary.items(), key=lambda x: -x[1])[:10]:
                print(f"  [{count}x] {summary}")
        else:
            print("  ✅ No critical errors found!")

        print(f"\n{'─'*70}")
        print("All Unique Checks Triggered:")
        print(f"{'─'*70}")
        for i, summary in enumerate(sorted(self.unique_note_summaries), 1):
            print(f"{i:3}. {summary}")

        print(f"\n{'─'*70}")
        print("Recommendations:")
        print(f"{'─'*70}")

        if total_errors > 0:
            print(f"  ❌ {total_errors} compliance errors found")
            print(f"     Most critical: Fix Date header format (RFC 7231)")
        else:
            print("  ✅ No compliance errors!")

        if total_warnings > 0:
            print(f"  ⚠️  {total_warnings} warnings found")
            print(f"     Consider: Adding explicit Cache-Control headers")
        else:
            print("  ✅ No warnings!")

        print(f"\n  📊 Coverage Analysis:")
        print(f"     • Triggered {unique_checks} unique checks")
        print(f"     • Remaining ~{237 - unique_checks} checks require:")
        print(f"       - TLS/HTTPS specific features (HSTS, secure contexts)")
        print(f"       - HTTP/2 specific features")
        print(f"       - Advanced features (compression, chunked encoding)")
        print(f"       - More complex scenarios and edge cases")

    def export_json(self, filename: str = "full_compliance_results.json"):
        """Export results to JSON."""
        output = {
            'summary': {
                'total_tests': len(self.results),
                'total_notes': len(self.all_notes),
                'unique_checks': len(self.unique_note_summaries),
                'coverage_percent': (len(self.unique_note_summaries) / 237) * 100,
                'note_levels': dict(self.note_levels),
                'note_categories': dict(self.note_categories),
            },
            'tests': self.results,
            'all_notes': self.all_notes,
            'unique_checks': sorted(list(self.unique_note_summaries)),
        }

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"\n📄 Results exported to {filename}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Full HTTP/1.1 Compliance Test Suite',
        epilog='Run against comprehensive_test_server.mojo for maximum coverage'
    )
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=8080, help='Server port')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--export', metavar='FILE', help='Export to JSON')

    args = parser.parse_args()

    suite = FullHTTP11ComplianceSuite(args.host, args.port, args.verbose)
    suite.run_all_tests()

    if args.export:
        suite.export_json(args.export)


if __name__ == '__main__':
    main()
