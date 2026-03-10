# -*- coding: utf-8 -*-
"""
OAuthHunter - Generic OAuth 2.0 / OIDC / SAML Vulnerability Scanner
Burp Suite Extension (Jython 2.7)

Features:
  - Passive: detects OAuth/SAML flows from ANY application automatically
  - Active: auto-generates and tests payloads for all major vuln classes
  - UI panel: real-time findings, flow graph, one-click attack launcher
  - No hardcoded URLs — works on any target

Install: Extender > Extensions > Add > Type: Python > Select this file
Requires: Burp Suite Pro + Jython 2.7 standalone jar
"""

from burp import IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory
from burp import IScanIssue, IExtensionStateListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JTextArea, JLabel, JSplitPane, JComboBox, JCheckBox,
                          JTextField, BorderFactory, JMenuItem, SwingUtilities,
                          JProgressBar, Box, BoxLayout, JOptionPane, JTree,
                          DefaultListModel, JList, JPopupMenu, SwingConstants)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel
from java.awt import (Color, Font, Dimension, BorderLayout, GridBagLayout,
                       GridBagConstraints, Insets, FlowLayout, GridLayout)
from java.awt.event import ActionListener, MouseAdapter
from java.net import URL
from java.util import ArrayList
from java.lang import Runnable, Thread
import json
import re
import base64
import urllib
import sys
import time
from collections import defaultdict

# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────
C_BG       = Color(18,  18,  24)
C_SURFACE  = Color(28,  28,  38)
C_BORDER   = Color(45,  45,  60)
C_ACCENT   = Color(99,  179, 237)
C_RED      = Color(252, 90,  90)
C_ORANGE   = Color(255, 165, 60)
C_GREEN    = Color(72,  199, 142)
C_YELLOW   = Color(255, 220, 80)
C_TEXT     = Color(220, 220, 235)
C_MUTED    = Color(120, 120, 150)
C_CRITICAL = Color(255, 60,  60)
C_HIGH     = Color(255, 130, 60)
C_MEDIUM   = Color(255, 210, 60)
C_LOW      = Color(72,  199, 142)
C_INFO     = Color(99,  179, 237)

SEVERITY_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}

# ─────────────────────────────────────────────
# OAUTH / SAML DETECTION SIGNATURES
# ─────────────────────────────────────────────
OAUTH_PARAMS = [
    "response_type", "client_id", "redirect_uri", "scope", "state",
    "code", "access_token", "id_token", "token_type", "grant_type",
    "code_verifier", "code_challenge", "nonce", "prompt", "RelayState",
    "SAMLResponse", "SAMLRequest", "returnTo", "return_to", "next",
    "redirect", "goto", "continue", "postLogin", "landingPage",
    "after_login", "g2g", "eg2g", "q2gExpiry", "wresult", "wctx", "wa",
]

OAUTH_PATHS = [
    "/authorize", "/oauth/authorize", "/oauth2/authorize",
    "/login/callback", "/auth/callback", "/oauth/callback",
    "/saml/acs", "/saml2/acs", "/sso/saml",
    "/token", "/oauth/token", "/oauth2/token",
    "/userinfo", "/oauth/userinfo",
    "/resume", "/authorize/resume",
    "/conversion/interceptor", "/auth/interceptor",
    "/.well-known/openid-configuration",
]

REDIRECT_PARAMS = [
    "redirect_uri", "returnTo", "return_to", "next", "redirect",
    "goto", "continue", "url", "target", "dest", "destination",
    "postLogin", "landingPage", "after_login", "callback",
    "redirect_url", "return_url", "success_url", "forward",
]

# ─────────────────────────────────────────────
# VULNERABILITY DEFINITIONS
# ─────────────────────────────────────────────
VULN_CHECKS = {
    "open_redirect_absolute": {
        "name": "Open Redirect via OAuth Redirect URI",
        "severity": "HIGH",
        "cwe": "CWE-601",
        "description": "redirect_uri accepts absolute external URLs",
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%40{original_host}",
            "https://{original_host}.evil.com",
            "https://evil.com/{original_path}",
        ],
    },
    "redirect_uri_prefix_bypass": {
        "name": "Auth0/OAuth Redirect URI Prefix Match Bypass",
        "severity": "HIGH",
        "cwe": "CWE-183",
        "description": "redirect_uri validated by prefix match, allowing query param injection",
        "payloads": [
            "{original_redirect_uri}?next={collab}",
            "{original_redirect_uri}?returnTo={collab}",
            "{original_redirect_uri}?redirect={collab}",
            "{original_redirect_uri}/../../../evil",
            "{original_redirect_uri}%2f..%2f..%2fevil",
            "{original_redirect_uri}#evil",
            "{original_redirect_uri}%23evil",
        ],
    },
    "state_missing": {
        "name": "Missing OAuth State Parameter (CSRF)",
        "severity": "HIGH",
        "cwe": "CWE-352",
        "description": "No state parameter in authorization request — CSRF possible",
        "payloads": [],
    },
    "state_predictable": {
        "name": "Predictable/Reusable OAuth State",
        "severity": "MEDIUM",
        "cwe": "CWE-330",
        "description": "State parameter appears short, sequential, or reusable",
        "payloads": [],
    },
    "state_injection": {
        "name": "OAuth State Parameter Injection",
        "severity": "MEDIUM",
        "cwe": "CWE-74",
        "description": "State parameter may carry redirect destination — tamper possible",
        "payloads": [
            '{"returnTo":"/admin"}',
            '{"returnTo":"/admin","role":"admin"}',
            "eyJyZXR1cm5UbyI6Ii9hZG1pbiJ9",  # base64 {"returnTo":"/admin"}
        ],
    },
    "implicit_flow": {
        "name": "OAuth Implicit Flow Detected",
        "severity": "MEDIUM",
        "cwe": "CWE-522",
        "description": "response_type=token exposes access token in URL fragment",
        "payloads": [],
    },
    "pkce_missing": {
        "name": "PKCE Not Enforced",
        "severity": "MEDIUM",
        "cwe": "CWE-345",
        "description": "No code_challenge/code_verifier — auth code interception possible",
        "payloads": [],
    },
    "scope_escalation": {
        "name": "OAuth Scope Escalation",
        "severity": "HIGH",
        "cwe": "CWE-269",
        "description": "Application may accept elevated scopes not originally requested",
        "payloads": [
            "openid profile email admin",
            "openid profile email offline_access",
            "read write admin",
            "openid profile email {original_scope} admin",
        ],
    },
    "token_in_url": {
        "name": "Access/ID Token Exposed in URL",
        "severity": "MEDIUM",
        "cwe": "CWE-598",
        "description": "Token transmitted in URL — logged in browser history and server logs",
        "payloads": [],
    },
    "redirect_param_injection": {
        "name": "Post-Auth Redirect Parameter Injection",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "description": "Application reads redirect destination from unvalidated parameter",
        "payloads": [
            "/admin", "/admin/users", "/config",
            "//admin", "/%2Fadmin",
            "/admin%00", "/admin%09",
            "/%5cadmin",
        ],
    },
    "cookie_interception_flag": {
        "name": "Auth State Cookie Missing Security Flags",
        "severity": "LOW",
        "cwe": "CWE-614",
        "description": "Cookies like g2g, returnTo, state missing HttpOnly/Secure/SameSite",
        "payloads": [],
    },
    "saml_signature_missing": {
        "name": "SAML Assertion Signature Not Enforced",
        "severity": "CRITICAL",
        "cwe": "CWE-347",
        "description": "SAMLResponse accepted without valid signature",
        "payloads": [],
    },
    "saml_relaystate_redirect": {
        "name": "SAML RelayState Open Redirect",
        "severity": "HIGH",
        "cwe": "CWE-601",
        "description": "RelayState parameter used as post-auth redirect without validation",
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "/admin",
            "/admin%00",
            "javascript:alert(1)",
        ],
    },
    "csrf_token_missing": {
        "name": "CSRF Token Not Present / Reusable",
        "severity": "MEDIUM",
        "cwe": "CWE-352",
        "description": "Login or callback form lacks CSRF protection",
        "payloads": [],
    },
    "interceptor_bypass": {
        "name": "Post-Auth Interceptor/Forced Redirect Bypass",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "description": "Post-authentication redirect enforcement may be bypassable",
        "payloads": [
            "g2g=false", "g2g=0", "g2g=",
            "eg2g=false",
            "?skip=true", "?bypass=1", "?debug=true",
        ],
    },
}

# ─────────────────────────────────────────────
# FLOW TRACKER
# ─────────────────────────────────────────────
class OAuthFlow(object):
    def __init__(self):
        self.requests  = []   # list of dicts
        self.params    = {}   # all observed OAuth params
        self.redirect_uris = set()
        self.state_values  = []
        self.client_ids    = set()
        self.scopes        = set()
        self.cookies       = {}
        self.hosts         = set()
        self.has_pkce      = False
        self.has_saml      = False
        self.has_wsfed     = False
        self.flow_type     = "unknown"  # oauth2, oidc, saml, wsfed
        self.findings      = []

    def add_request(self, req_dict):
        self.requests.append(req_dict)
        self.hosts.add(req_dict.get("host", ""))

    def to_dict(self):
        return {
            "hosts": list(self.hosts),
            "flow_type": self.flow_type,
            "client_ids": list(self.client_ids),
            "scopes": list(self.scopes),
            "redirect_uris": list(self.redirect_uris),
            "state_count": len(self.state_values),
            "has_pkce": self.has_pkce,
            "has_saml": self.has_saml,
            "request_count": len(self.requests),
        }


# ─────────────────────────────────────────────
# MAIN EXTENSION CLASS
# ─────────────────────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("OAuthHunter")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        # State
        self.flows         = defaultdict(OAuthFlow)  # host -> OAuthFlow
        self.all_findings  = []
        self.active_jobs   = []
        self.collab_url    = ""
        self._paused       = False

        # Build UI on EDT
        SwingUtilities.invokeLater(UIBuilder(self))
        callbacks.addSuiteTab(self)

        self._log("OAuthHunter loaded. Monitoring all traffic...")

    # ── ITab ──
    def getTabCaption(self): return "OAuthHunter"
    def getUiComponent(self): return self._main_panel

    def extensionUnloaded(self):
        self._log("OAuthHunter unloaded.")

    # ── HTTP Listener ──
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self._paused:
            return
        try:
            if messageIsRequest:
                self._process_request(messageInfo)
            else:
                self._process_response(messageInfo)
        except Exception as e:
            self._log("processHttpMessage error: " + str(e))

    # ─────────────────────────────────────────
    # REQUEST ANALYSIS
    # ─────────────────────────────────────────
    def _process_request(self, messageInfo):
        req     = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(messageInfo)
        url      = analyzed.getUrl()
        host     = url.getHost()
        path     = url.getPath()
        params   = analyzed.getParameters()

        flow = self.flows[host]
        flow.hosts.add(host)

        param_map = {}
        for p in params:
            param_map[p.getName()] = p.getValue()

        # Detect OAuth/SAML involvement
        is_oauth = any(k in param_map for k in OAUTH_PARAMS)
        is_oauth = is_oauth or any(seg in path for seg in OAUTH_PATHS)

        if not is_oauth:
            return

        req_dict = {
            "host": host,
            "path": path,
            "method": analyzed.getMethod(),
            "params": param_map,
            "timestamp": time.strftime("%H:%M:%S"),
            "messageInfo": messageInfo,
        }
        flow.add_request(req_dict)

        # Extract key OAuth params
        if "client_id" in param_map:
            flow.client_ids.add(param_map["client_id"])
        if "scope" in param_map:
            flow.scopes.add(param_map["scope"])
        if "redirect_uri" in param_map:
            flow.redirect_uris.add(param_map["redirect_uri"])
        if "state" in param_map:
            flow.state_values.append(param_map["state"])
        if "code_challenge" in param_map:
            flow.has_pkce = True
        if "SAMLRequest" in param_map or "SAMLResponse" in param_map:
            flow.has_saml = True
            flow.flow_type = "saml"
        if "wresult" in param_map:
            flow.has_wsfed = True
            flow.flow_type = "wsfed"
        if "response_type" in param_map:
            rt = param_map["response_type"]
            if "token" in rt and "code" not in rt:
                flow.flow_type = "oauth2_implicit"
                self._add_finding(host, "implicit_flow", path, param_map, messageInfo)
            elif "code" in rt:
                flow.flow_type = "oauth2_code"

        # Passive checks
        self._passive_check(host, path, param_map, messageInfo, flow)

        # Update UI
        self._update_flow_panel(host, flow)

    # ─────────────────────────────────────────
    # RESPONSE ANALYSIS
    # ─────────────────────────────────────────
    def _process_response(self, messageInfo):
        req      = messageInfo.getRequest()
        resp     = messageInfo.getResponse()
        analyzed_req  = self._helpers.analyzeRequest(messageInfo)
        analyzed_resp = self._helpers.analyzeResponse(resp)
        url      = analyzed_req.getUrl()
        host     = url.getHost()
        status   = analyzed_resp.getStatusCode()
        headers  = analyzed_resp.getHeaders()

        flow = self.flows[host]

        header_map = {}
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                header_map[k.strip().lower()] = v.strip()

        # Check cookies
        for h in headers:
            if h.lower().startswith("set-cookie:"):
                cookie_str = h[11:].strip()
                cname = cookie_str.split("=")[0].strip()
                # Check security flags
                missing_flags = []
                if "httponly" not in cookie_str.lower() and cname in [
                    "auth0", "auth0_compat", "state", "session", "token"]:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_str.lower():
                    missing_flags.append("Secure")
                if "samesite" not in cookie_str.lower():
                    missing_flags.append("SameSite")

                if missing_flags and cname.lower() in [
                    "g2g", "eg2g", "returnto", "state", "q2gexpiry",
                    "auth0", "session", "token", "access_token"]:
                    self._add_finding(host, "cookie_interception_flag",
                                     analyzed_req.getUrl().getPath(),
                                     {"cookie": cname, "missing": str(missing_flags)},
                                     messageInfo)

        # Check token in Location header
        location = header_map.get("location", "")
        if location:
            if "access_token=" in location or "id_token=" in location:
                self._add_finding(host, "token_in_url",
                                 analyzed_req.getUrl().getPath(),
                                 {"location": location[:100]}, messageInfo)

            # Detect redirect with error info (like the airmiles case)
            if "error=unauthorized_client" in location or "error_description=" in location:
                decoded = urllib.unquote(location)
                self._add_finding(host, "redirect_uri_prefix_bypass",
                                 "Error response reveals callback whitelist",
                                 {"location": decoded[:200]}, messageInfo,
                                 confidence="Tentative")

    # ─────────────────────────────────────────
    # PASSIVE CHECKS
    # ─────────────────────────────────────────
    def _passive_check(self, host, path, params, messageInfo, flow):
        # 1. Missing state
        if "response_type" in params and "state" not in params:
            self._add_finding(host, "state_missing", path, params, messageInfo)

        # 2. Weak state
        if "state" in params:
            s = params["state"]
            if len(s) < 8 or s.isdigit() or s in ["1", "0", "null", "undefined"]:
                self._add_finding(host, "state_predictable", path,
                                  {"state": s}, messageInfo)
            # Check if state looks JWT-ish with decodeable claims
            if "." in s and len(s.split(".")) == 3:
                decoded = self._try_decode_jwt(s)
                if decoded and any(k in str(decoded) for k in
                                   ["returnTo", "redirect", "next", "url"]):
                    self._add_finding(host, "state_injection", path,
                                      {"state_claims": str(decoded)[:200]},
                                      messageInfo, confidence="Firm")

        # 3. PKCE missing for code flow
        if params.get("response_type") == "code" and not flow.has_pkce:
            self._add_finding(host, "pkce_missing", path, params, messageInfo)

        # 4. Redirect params present
        for rp in REDIRECT_PARAMS:
            if rp in params:
                val = params[rp]
                if val.startswith("http") or val.startswith("//"):
                    self._add_finding(host, "open_redirect_absolute", path,
                                      {rp: val}, messageInfo)
                else:
                    self._add_finding(host, "redirect_param_injection", path,
                                      {rp: val}, messageInfo, confidence="Tentative")

        # 5. SAML RelayState
        if "RelayState" in params:
            rs = params["RelayState"]
            if rs.startswith("http") or "/" in rs:
                self._add_finding(host, "saml_relaystate_redirect", path,
                                  {"RelayState": rs}, messageInfo)

        # 6. Interceptor / forced redirect pattern
        if any(x in path for x in ["interceptor", "convert", "intercept",
                                    "force", "landing", "post-login"]):
            self._add_finding(host, "interceptor_bypass", path,
                              params, messageInfo, confidence="Tentative")

        # 7. g2g / conversion cookies in params
        if any(x in params for x in ["g2g", "eg2g", "q2gExpiry"]):
            self._add_finding(host, "interceptor_bypass", path,
                              {k: params[k] for k in ["g2g","eg2g","q2gExpiry"]
                               if k in params}, messageInfo)

    # ─────────────────────────────────────────
    # ACTIVE ATTACK ENGINE
    # ─────────────────────────────────────────
    def launch_active_tests(self, host, finding_type, original_msg):
        """Launch active tests for a specific finding from UI"""
        check = VULN_CHECKS.get(finding_type, {})
        payloads = check.get("payloads", [])
        if not payloads:
            self._log("No active payloads for: " + finding_type)
            return

        self._log("Launching active tests for: {} on {}".format(finding_type, host))

        def run():
            flow = self.flows.get(host)
            results = []

            for payload in payloads:
                try:
                    result = self._send_payload(finding_type, payload,
                                                original_msg, flow)
                    results.append(result)
                    self._update_active_results(result)
                    time.sleep(0.3)
                except Exception as e:
                    self._log("Payload error: " + str(e))

            self._log("Active tests complete. {} results.".format(len(results)))
            SwingUtilities.invokeLater(lambda: self._refresh_findings_table())

        t = Thread(run)
        t.setDaemon(True)
        t.start()

    def _send_payload(self, finding_type, payload, original_msg, flow):
        """Build and send a modified request with a payload"""
        req       = original_msg.getRequest()
        analyzed  = self._helpers.analyzeRequest(original_msg)
        url       = analyzed.getUrl()
        host      = url.getHost()
        params    = analyzed.getParameters()

        # Resolve template variables
        original_redir = ""
        for p in params:
            if p.getName() == "redirect_uri":
                original_redir = p.getValue()
                break

        collab = self.collab_url or "https://oauthhunter-collab.example.com"

        payload = payload.replace("{original_redirect_uri}", original_redir)
        payload = payload.replace("{original_host}", host)
        payload = payload.replace("{original_path}", url.getPath())
        payload = payload.replace("{collab}", collab)
        payload = payload.replace("{original_scope}",
                                  "openid" if not flow else
                                  " ".join(flow.scopes))

        # Determine which param to inject
        target_params = {
            "open_redirect_absolute":    ["redirect_uri"],
            "redirect_uri_prefix_bypass":["redirect_uri"],
            "state_injection":           ["state"],
            "scope_escalation":          ["scope"],
            "redirect_param_injection":  REDIRECT_PARAMS,
            "saml_relaystate_redirect":  ["RelayState"],
        }

        inject_into = target_params.get(finding_type, ["redirect_uri"])
        modified_req = req

        for param_name in inject_into:
            for p in params:
                if p.getName() == param_name:
                    modified_req = self._helpers.updateParameter(
                        modified_req,
                        self._helpers.buildParameter(
                            param_name, payload, p.getType()
                        )
                    )
                    break

        # Send
        try:
            http_service = original_msg.getHttpService()
            resp_msg     = self._callbacks.makeHttpRequest(http_service, modified_req)
            resp         = resp_msg.getResponse()
            analyzed_resp = self._helpers.analyzeResponse(resp)
            status       = analyzed_resp.getStatusCode()

            # Check for success indicators
            resp_str = self._helpers.bytesToString(resp)
            headers  = analyzed_resp.getHeaders()
            location = ""
            for h in headers:
                if h.lower().startswith("location:"):
                    location = h[9:].strip()

            success = self._evaluate_success(finding_type, payload,
                                             status, location, resp_str)

            return {
                "finding_type": finding_type,
                "payload":      payload[:80],
                "status":       status,
                "location":     location[:100],
                "success":      success,
                "request":      resp_msg,
                "timestamp":    time.strftime("%H:%M:%S"),
            }
        except Exception as e:
            return {
                "finding_type": finding_type,
                "payload":      payload[:80],
                "status":       0,
                "location":     "",
                "success":      False,
                "error":        str(e),
                "timestamp":    time.strftime("%H:%M:%S"),
            }

    def _evaluate_success(self, finding_type, payload, status, location, body):
        """Determine if a payload triggered a vulnerability"""
        if finding_type in ["open_redirect_absolute", "redirect_uri_prefix_bypass"]:
            return ("evil.com" in location or
                    "oauthhunter-collab" in location or
                    (status in [301, 302] and "error" not in location.lower()))
        if finding_type == "scope_escalation":
            return status == 302 and "error" not in location.lower()
        if finding_type == "state_injection":
            return status in [200, 302] and "error" not in location.lower()
        if finding_type == "redirect_param_injection":
            return ("/admin" in location or
                    status in [200, 302] and "intercept" not in location.lower())
        if finding_type == "interceptor_bypass":
            return (status == 200 and "intercept" not in body.lower()[:500])
        if finding_type == "saml_relaystate_redirect":
            return "evil.com" in location or "/admin" in location
        return status not in [400, 401, 403, 500]

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────
    def _add_finding(self, host, vuln_type, path, params,
                     messageInfo, confidence="Certain"):
        check = VULN_CHECKS.get(vuln_type, {})
        finding = {
            "host":        host,
            "vuln_type":   vuln_type,
            "name":        check.get("name", vuln_type),
            "severity":    check.get("severity", "INFO"),
            "cwe":         check.get("cwe", ""),
            "description": check.get("description", ""),
            "path":        path,
            "params":      params,
            "confidence":  confidence,
            "messageInfo": messageInfo,
            "timestamp":   time.strftime("%H:%M:%S"),
            "active_results": [],
        }

        # Deduplicate
        for f in self.all_findings:
            if (f["host"] == host and f["vuln_type"] == vuln_type
                    and f["path"] == path):
                return

        self.all_findings.append(finding)
        self.flows[host].findings.append(finding)
        self._log("[{}] {} on {}{}".format(
            finding["severity"], finding["name"], host, path))
        SwingUtilities.invokeLater(lambda: self._refresh_findings_table())

    def _try_decode_jwt(self, token):
        parts = token.split(".")
        if len(parts) < 2:
            return None
        try:
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            try:
                raw = base64.b64decode(token + "==")
                return json.loads(raw)
            except Exception:
                return None

    def _log(self, msg):
        try:
            ts = time.strftime("%H:%M:%S")
            line = "[{}] {}\n".format(ts, msg)
            SwingUtilities.invokeLater(lambda: self._append_log(line))
        except Exception:
            pass

    def _append_log(self, line):
        try:
            self._log_area.append(line)
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        except Exception:
            pass

    def _update_flow_panel(self, host, flow):
        SwingUtilities.invokeLater(lambda: self._refresh_flow_tree(host, flow))

    def _update_active_results(self, result):
        SwingUtilities.invokeLater(lambda: self._append_active_result(result))

    def _refresh_findings_table(self):
        try:
            model = self._findings_table_model
            model.setRowCount(0)
            for f in self.all_findings:
                model.addRow([
                    f["timestamp"],
                    f["host"],
                    f["severity"],
                    f["name"],
                    f["path"][:60],
                    f["confidence"],
                    f["cwe"],
                ])
        except Exception as e:
            pass

    def _refresh_flow_tree(self, host, flow):
        try:
            root = self._flow_tree_root
            # Find or create host node
            host_node = None
            for i in range(root.getChildCount()):
                if str(root.getChildAt(i)) == host:
                    host_node = root.getChildAt(i)
                    break
            if not host_node:
                host_node = DefaultMutableTreeNode(host)
                root.add(host_node)

            host_node.removeAllChildren()
            host_node.add(DefaultMutableTreeNode(
                "Flow: " + flow.flow_type))
            host_node.add(DefaultMutableTreeNode(
                "Requests: " + str(len(flow.requests))))
            if flow.client_ids:
                cid_node = DefaultMutableTreeNode("Client IDs")
                for cid in flow.client_ids:
                    cid_node.add(DefaultMutableTreeNode(cid[:40]))
                host_node.add(cid_node)
            if flow.redirect_uris:
                rdir_node = DefaultMutableTreeNode("Redirect URIs")
                for ru in flow.redirect_uris:
                    rdir_node.add(DefaultMutableTreeNode(ru[:60]))
                host_node.add(rdir_node)
            if flow.scopes:
                scope_node = DefaultMutableTreeNode("Scopes")
                for s in flow.scopes:
                    scope_node.add(DefaultMutableTreeNode(s))
                host_node.add(scope_node)
            if flow.state_values:
                host_node.add(DefaultMutableTreeNode(
                    "States seen: " + str(len(flow.state_values))))
            host_node.add(DefaultMutableTreeNode(
                "PKCE: " + ("YES" if flow.has_pkce else "NO")))
            host_node.add(DefaultMutableTreeNode(
                "Findings: " + str(len(flow.findings))))

            self._flow_tree_model.reload()
            self._flow_tree.expandRow(0)
        except Exception:
            pass

    def _append_active_result(self, result):
        try:
            model = self._active_table_model
            icon = "✓" if result.get("success") else "✗"
            model.addRow([
                result["timestamp"],
                icon,
                result["finding_type"],
                result["payload"][:50],
                str(result["status"]),
                result["location"][:60],
            ])
        except Exception:
            pass


# ─────────────────────────────────────────────
# UI BUILDER
# ─────────────────────────────────────────────
class UIBuilder(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        e = self.ext
        main = JPanel(BorderLayout())
        main.setBackground(C_BG)
        e._main_panel = main

        tabs = JTabbedPane()
        tabs.setBackground(C_SURFACE)
        tabs.setForeground(C_TEXT)
        tabs.setFont(Font("Monospaced", Font.BOLD, 12))

        # ── Tab 1: Findings ──
        tabs.addTab("⚠  Findings", self._build_findings_tab())
        # ── Tab 2: Flow Graph ──
        tabs.addTab("⊙  Flow Map", self._build_flow_tab())
        # ── Tab 3: Active Attacks ──
        tabs.addTab("⚡ Active Tests", self._build_active_tab())
        # ── Tab 4: Payloads ──
        tabs.addTab("⊞  Payload Library", self._build_payloads_tab())
        # ── Tab 5: Settings ──
        tabs.addTab("⚙  Settings", self._build_settings_tab())
        # ── Tab 6: Log ──
        tabs.addTab("◈  Log", self._build_log_tab())

        main.add(self._build_header(), BorderLayout.NORTH)
        main.add(tabs, BorderLayout.CENTER)

    def _build_header(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_SURFACE)
        panel.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, C_ACCENT))

        title = JLabel("  ◈ OAuthHunter  —  Generic OAuth / OIDC / SAML Vulnerability Scanner")
        title.setFont(Font("Monospaced", Font.BOLD, 14))
        title.setForeground(C_ACCENT)

        btns = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 6))
        btns.setBackground(C_SURFACE)

        pause_btn = JButton("⏸  Pause")
        pause_btn.setFont(Font("Monospaced", Font.PLAIN, 11))
        pause_btn.setBackground(C_SURFACE)
        pause_btn.setForeground(C_YELLOW)

        clear_btn = JButton("⌫  Clear")
        clear_btn.setFont(Font("Monospaced", Font.PLAIN, 11))
        clear_btn.setBackground(C_SURFACE)
        clear_btn.setForeground(C_MUTED)

        export_btn = JButton("↑  Export JSON")
        export_btn.setFont(Font("Monospaced", Font.PLAIN, 11))
        export_btn.setBackground(C_SURFACE)
        export_btn.setForeground(C_GREEN)

        class PauseListener(ActionListener):
            def actionPerformed(self, evt):
                e._paused = not e._paused
                pause_btn.setText("▶  Resume" if e._paused else "⏸  Pause")
                pause_btn.setForeground(C_GREEN if e._paused else C_YELLOW)

        class ClearListener(ActionListener):
            def actionPerformed(self, evt):
                e.all_findings = []
                e.flows.clear()
                e._findings_table_model.setRowCount(0)
                e._active_table_model.setRowCount(0)
                e._flow_tree_root.removeAllChildren()
                e._flow_tree_model.reload()
                e._log("Cleared all findings and flows.")

        class ExportListener(ActionListener):
            def actionPerformed(self, evt):
                try:
                    data = []
                    for f in e.all_findings:
                        data.append({k: v for k, v in f.items()
                                     if k not in ("messageInfo", "active_results")})
                    path = "/tmp/oauthhunter_findings.json"
                    with open(path, "w") as fp:
                        json.dump(data, fp, indent=2, default=str)
                    e._log("Exported to " + path)
                    JOptionPane.showMessageDialog(None,
                        "Exported to " + path, "Export OK",
                        JOptionPane.INFORMATION_MESSAGE)
                except Exception as ex:
                    e._log("Export error: " + str(ex))

        pause_btn.addActionListener(PauseListener())
        clear_btn.addActionListener(ClearListener())
        export_btn.addActionListener(ExportListener())

        btns.add(pause_btn)
        btns.add(clear_btn)
        btns.add(export_btn)

        panel.add(title, BorderLayout.WEST)
        panel.add(btns, BorderLayout.EAST)
        return panel

    def _build_findings_tab(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)

        cols = ["Time", "Host", "Severity", "Vulnerability", "Path",
                "Confidence", "CWE"]
        model = DefaultTableModel(cols, 0) {
            def isCellEditable(self, r, c): return False
        }
        # Python workaround for anonymous subclass
        class NonEditableModel(DefaultTableModel):
            def isCellEditable(self, row, col):
                return False
        model = NonEditableModel(cols, 0)
        e._findings_table_model = model

        table = JTable(model)
        table.setBackground(C_SURFACE)
        table.setForeground(C_TEXT)
        table.setGridColor(C_BORDER)
        table.setSelectionBackground(C_ACCENT)
        table.setFont(Font("Monospaced", Font.PLAIN, 11))
        table.getTableHeader().setBackground(C_BG)
        table.getTableHeader().setForeground(C_ACCENT)
        table.getTableHeader().setFont(Font("Monospaced", Font.BOLD, 11))
        table.setRowHeight(22)

        # Color severity column
        class SeverityRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
                c = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, tbl, val, sel, foc, row, col)
                if col == 2:
                    color = SEVERITY_COLORS.get(str(val), C_TEXT)
                    self.setForeground(color)
                    self.setFont(Font("Monospaced", Font.BOLD, 11))
                else:
                    self.setForeground(C_TEXT)
                    self.setFont(Font("Monospaced", Font.PLAIN, 11))
                self.setBackground(C_SURFACE if not sel else C_ACCENT.darker())
                return c

        renderer = SeverityRenderer()
        for i in range(len(cols)):
            table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        table.getColumnModel().getColumn(0).setPreferredWidth(70)
        table.getColumnModel().getColumn(1).setPreferredWidth(180)
        table.getColumnModel().getColumn(2).setPreferredWidth(80)
        table.getColumnModel().getColumn(3).setPreferredWidth(280)
        table.getColumnModel().getColumn(4).setPreferredWidth(200)
        table.getColumnModel().getColumn(5).setPreferredWidth(80)
        table.getColumnModel().getColumn(6).setPreferredWidth(80)

        # Detail panel
        detail = JTextArea()
        detail.setBackground(C_BG)
        detail.setForeground(C_TEXT)
        detail.setFont(Font("Monospaced", Font.PLAIN, 11))
        detail.setEditable(False)
        detail.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Attack button
        attack_btn = JButton("⚡ Launch Active Tests for Selected")
        attack_btn.setFont(Font("Monospaced", Font.BOLD, 12))
        attack_btn.setBackground(C_RED)
        attack_btn.setForeground(Color.WHITE)

        class SelectionListener(MouseAdapter):
            def mouseClicked(self, evt):
                row = table.getSelectedRow()
                if row >= 0 and row < len(e.all_findings):
                    f = e.all_findings[row]
                    text = (
                        "Vulnerability: {}\n"
                        "Severity:      {}\n"
                        "CWE:           {}\n"
                        "Host:          {}\n"
                        "Path:          {}\n"
                        "Confidence:    {}\n"
                        "Time:          {}\n\n"
                        "Description:\n{}\n\n"
                        "Observed Parameters:\n{}\n\n"
                        "Suggested Payloads:\n{}"
                    ).format(
                        f["name"], f["severity"], f["cwe"],
                        f["host"], f["path"], f["confidence"],
                        f["timestamp"], f["description"],
                        json.dumps(f["params"], indent=2, default=str)[:500],
                        "\n".join(VULN_CHECKS.get(f["vuln_type"], {})
                                  .get("payloads", ["(passive check only)"])[:10])
                    )
                    detail.setText(text)

        table.addMouseListener(SelectionListener())

        class AttackListener(ActionListener):
            def actionPerformed(self, evt):
                row = table.getSelectedRow()
                if row >= 0 and row < len(e.all_findings):
                    f = e.all_findings[row]
                    e.launch_active_tests(f["host"], f["vuln_type"],
                                          f["messageInfo"])
                    tabs = e._main_panel.getComponent(1)
                    tabs.setSelectedIndex(2)

        attack_btn.addActionListener(AttackListener())

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(table),
                           JScrollPane(detail))
        split.setResizeWeight(0.6)
        split.setBackground(C_BG)

        bottom = JPanel(BorderLayout())
        bottom.setBackground(C_BG)
        bottom.add(attack_btn, BorderLayout.EAST)

        panel.add(split, BorderLayout.CENTER)
        panel.add(bottom, BorderLayout.SOUTH)
        return panel

    def _build_flow_tab(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)

        root = DefaultMutableTreeNode("Detected OAuth Flows")
        e._flow_tree_root = root
        tree_model = DefaultTreeModel(root)
        e._flow_tree_model = tree_model

        tree = JTree(tree_model)
        tree.setBackground(C_SURFACE)
        tree.setForeground(C_TEXT)
        tree.setFont(Font("Monospaced", Font.PLAIN, 11))
        e._flow_tree = tree

        detail = JTextArea()
        detail.setBackground(C_BG)
        detail.setForeground(C_ACCENT)
        detail.setFont(Font("Monospaced", Font.PLAIN, 11))
        detail.setEditable(False)
        detail.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        class TreeListener(MouseAdapter):
            def mouseClicked(self, evt):
                path = tree.getSelectionPath()
                if not path:
                    return
                node = path.getLastPathComponent()
                label = str(node)
                for host, flow in e.flows.items():
                    if host == label:
                        detail.setText(json.dumps(flow.to_dict(), indent=2))
                        return

        tree.addMouseListener(TreeListener())

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                           JScrollPane(tree),
                           JScrollPane(detail))
        split.setResizeWeight(0.35)

        lbl = JLabel("  OAuth/OIDC/SAML flows detected passively from proxied traffic")
        lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        lbl.setForeground(C_MUTED)

        panel.add(lbl, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)
        return panel

    def _build_active_tab(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)

        cols = ["Time", "Result", "Vuln Type", "Payload", "Status", "Location"]
        class NonEditableModel(DefaultTableModel):
            def isCellEditable(self, row, col):
                return False
        model = NonEditableModel(cols, 0)
        e._active_table_model = model

        table = JTable(model)
        table.setBackground(C_SURFACE)
        table.setForeground(C_TEXT)
        table.setGridColor(C_BORDER)
        table.setFont(Font("Monospaced", Font.PLAIN, 11))
        table.getTableHeader().setBackground(C_BG)
        table.getTableHeader().setForeground(C_ACCENT)
        table.getTableHeader().setFont(Font("Monospaced", Font.BOLD, 11))
        table.setRowHeight(22)

        class ResultRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
                c = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, tbl, val, sel, foc, row, col)
                if col == 1:
                    self.setForeground(C_GREEN if str(val) == "✓" else C_MUTED)
                    self.setFont(Font("Monospaced", Font.BOLD, 14))
                else:
                    self.setForeground(C_TEXT)
                    self.setFont(Font("Monospaced", Font.PLAIN, 11))
                self.setBackground(C_SURFACE if not sel else C_ACCENT.darker())
                return c

        renderer = ResultRenderer()
        for i in range(len(cols)):
            table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        lbl = JLabel("  Active test results — payloads sent automatically from Findings tab")
        lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        lbl.setForeground(C_MUTED)

        panel.add(lbl, BorderLayout.NORTH)
        panel.add(JScrollPane(table), BorderLayout.CENTER)
        return panel

    def _build_payloads_tab(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)

        left = JPanel()
        left.setLayout(BoxLayout(left, BoxLayout.Y_AXIS))
        left.setBackground(C_SURFACE)

        right = JTextArea()
        right.setBackground(C_BG)
        right.setForeground(C_TEXT)
        right.setFont(Font("Monospaced", Font.PLAIN, 11))
        right.setEditable(True)
        right.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        for vuln_type, check in sorted(VULN_CHECKS.items()):
            btn = JButton(check["name"][:45])
            btn.setFont(Font("Monospaced", Font.PLAIN, 10))
            btn.setBackground(C_SURFACE)
            sev = check.get("severity", "INFO")
            btn.setForeground(SEVERITY_COLORS.get(sev, C_TEXT))
            btn.setMaximumSize(Dimension(380, 28))
            btn.setHorizontalAlignment(SwingConstants.LEFT)

            payloads = check.get("payloads", [])
            payload_text = (
                "# {}\n# Severity: {} | {}\n# {}\n\n"
                "Payloads:\n{}"
            ).format(
                check["name"], check["severity"],
                check["cwe"], check["description"],
                "\n".join(payloads) if payloads else "(passive detection only)"
            )

            class BtnListener(ActionListener):
                def __init__(self, txt):
                    self._txt = txt
                def actionPerformed(self, evt):
                    right.setText(self._txt)

            btn.addActionListener(BtnListener(payload_text))
            left.add(btn)

        lbl = JLabel("  Click a vulnerability class to view payloads")
        lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        lbl.setForeground(C_MUTED)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                           JScrollPane(left),
                           JScrollPane(right))
        split.setResizeWeight(0.4)

        panel.add(lbl, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)
        return panel

    def _build_settings_tab(self):
        e = self.ext
        panel = JPanel(GridBagLayout())
        panel.setBackground(C_BG)
        gbc = GridBagConstraints()
        gbc.insets = Insets(8, 12, 8, 12)
        gbc.fill = GridBagConstraints.HORIZONTAL

        def add_row(label, widget, row):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, row, 0
            lbl = JLabel(label)
            lbl.setFont(Font("Monospaced", Font.BOLD, 11))
            lbl.setForeground(C_ACCENT)
            panel.add(lbl, gbc)
            gbc.gridx, gbc.weightx = 1, 1.0
            panel.add(widget, gbc)

        collab_field = JTextField(e.collab_url or "https://your-collaborator.net", 35)
        collab_field.setBackground(C_SURFACE)
        collab_field.setForeground(C_TEXT)
        collab_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        passive_cb = JCheckBox("Enable passive detection", True)
        passive_cb.setBackground(C_BG)
        passive_cb.setForeground(C_TEXT)
        passive_cb.setFont(Font("Monospaced", Font.PLAIN, 11))

        active_cb = JCheckBox("Enable active tests (launches real requests)", False)
        active_cb.setBackground(C_BG)
        active_cb.setForeground(C_TEXT)
        active_cb.setFont(Font("Monospaced", Font.PLAIN, 11))

        scope_field = JTextField("amsqa.airmiles.ca,oauth-int.airmiles.ca", 35)
        scope_field.setBackground(C_SURFACE)
        scope_field.setForeground(C_TEXT)
        scope_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        save_btn = JButton("Save Settings")
        save_btn.setFont(Font("Monospaced", Font.BOLD, 11))
        save_btn.setBackground(C_GREEN)
        save_btn.setForeground(C_BG)

        class SaveListener(ActionListener):
            def actionPerformed(self, evt):
                e.collab_url = collab_field.getText().strip()
                e._log("Settings saved. Collaborator: " + e.collab_url)

        save_btn.addActionListener(SaveListener())

        add_row("Collaborator URL:", collab_field, 0)
        add_row("Scope (comma-sep hosts):", scope_field, 1)
        add_row("", passive_cb, 2)
        add_row("", active_cb, 3)

        gbc.gridx, gbc.gridy, gbc.gridwidth = 1, 4, 1
        panel.add(save_btn, gbc)

        # Info box
        info = JTextArea(
            "\nOAuthHunter works fully passively — just browse the target\n"
            "normally through Burp and the extension auto-detects flows.\n\n"
            "To run active tests:\n"
            "  1. Browse through a login flow\n"
            "  2. Go to Findings tab\n"
            "  3. Select a finding\n"
            "  4. Click 'Launch Active Tests'\n\n"
            "Findings are exported to /tmp/oauthhunter_findings.json\n"
        )
        info.setBackground(C_SURFACE)
        info.setForeground(C_MUTED)
        info.setFont(Font("Monospaced", Font.PLAIN, 11))
        info.setEditable(False)
        info.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        gbc.gridx, gbc.gridy, gbc.gridwidth, gbc.weighty = 0, 5, 2, 1.0
        gbc.fill = GridBagConstraints.BOTH
        panel.add(JScrollPane(info), gbc)

        return panel

    def _build_log_tab(self):
        e = self.ext
        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)

        log = JTextArea()
        log.setBackground(C_BG)
        log.setForeground(C_MUTED)
        log.setFont(Font("Monospaced", Font.PLAIN, 10))
        log.setEditable(False)
        log.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        e._log_area = log

        clear_btn = JButton("Clear Log")
        clear_btn.setFont(Font("Monospaced", Font.PLAIN, 10))
        clear_btn.setBackground(C_SURFACE)
        clear_btn.setForeground(C_MUTED)

        class ClearLog(ActionListener):
            def actionPerformed(self, evt):
                log.setText("")

        clear_btn.addActionListener(ClearLog())

        panel.add(JScrollPane(log), BorderLayout.CENTER)
        panel.add(clear_btn, BorderLayout.SOUTH)
        return panel
