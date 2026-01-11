# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension (Deep Optimized)
Focused JavaScript analysis with strict endpoint filtering to reduce noise.
Maximum performance through early-exit, single-pass extraction, and lazy validation.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import re
import inspect

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel


# ==================== OPTIMIZED PATTERNS ====================
# All patterns use non-capturing groups (?:) for faster matching

# Combined endpoint pattern - single alternation regex
_ENDPOINT_PAT = re.compile(
    r'["\']('
    r'(?:https?:)?//[^"\']*/api/[a-zA-Z0-9/_-]+|'
    r'/api/v?\d*/[a-zA-Z0-9/_-]{2,}|'
    r'/v\d+/[a-zA-Z0-9/_-]{2,}|'
    r'/rest/[a-zA-Z0-9/_-]{2,}|'
    r'/graphql[a-zA-Z0-9/_-]*|'
    r'/oauth[0-9]*/[a-zA-Z0-9/_-]+|'
    r'/auth[a-zA-Z0-9/_-]*|'
    r'/login[a-zA-Z0-9/_-]*|'
    r'/logout[a-zA-Z0-9/_-]*|'
    r'/token[a-zA-Z0-9/_-]*|'
    r'/admin[a-zA-Z0-9/_-]*|'
    r'/dashboard[a-zA-Z0-9/_-]*|'
    r'/internal[a-zA-Z0-9/_-]*|'
    r'/debug[a-zA-Z0-9/_-]*|'
    r'/config[a-zA-Z0-9/_-]*|'
    r'/backup[a-zA-Z0-9/_-]*|'
    r'/private[a-zA-Z0-9/_-]*|'
    r'/upload[a-zA-Z0-9/_-]*|'
    r'/download[a-zA-Z0-9/_-]*|'
    r'/\.well-known/[a-zA-Z0-9/_-]+|'
    r'/idp/[a-zA-Z0-9/_-]+'
    r')["\']',
    re.IGNORECASE
)

# Combined URL pattern
_URL_PAT = re.compile(
    r'(?:'
    r'["\'](?P<u1>https?://[^\s"\'<>]{10,})["\']|'
    r'["\'](?P<u2>wss?://[^\s"\'<>]{10,})["\']|'
    r'["\'](?P<u3>sftp://[^\s"\'<>]{10,})["\']|'
    r'(?P<s3>https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)|'
    r'(?P<az>https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)|'
    r'(?P<gc>https?://storage\.googleapis\.com/[^\s"\'<>]*)'
    r')'
)

# Combined secret pattern - single pass for all secrets
_SECRET_PAT = re.compile(
    r'(?:'
    r'(?P<aws>AKIA[0-9A-Z]{16})|'
    r'(?P<gapi>AIza[0-9A-Za-z\-_]{35})|'
    r'(?P<stripe>sk_live_[0-9a-zA-Z]{24,})|'
    r'(?P<ghpat>ghp_[0-9a-zA-Z]{36})|'
    r'(?P<slack>xox[baprs]-[0-9a-zA-Z\-]{10,48})|'
    r'(?P<jwt>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)|'
    r'(?P<pkey>-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)|'
    r'(?P<mongo>mongodb(?:\+srv)?://[^\s"\'<>]+)|'
    r'(?P<pg>postgres(?:ql)?://[^\s"\'<>]+)|'
    r'(?P<mysql>mysql://[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)|'
    r'(?P<segpub>sgp_[A-Z0-9_-]{60,70})|'
    r'(?P<fbtok>EAACEdEose0cBA[A-Z0-9]{20,})|'
    r'(?P<goauth>ya29\.[a-z0-9_-]{30,})'
    r')'
)

# Case-insensitive secret patterns (separate for performance - only run if needed)
_SECRET_CI_PAT = re.compile(
    r'(?:'
    r'algolia.{0,32}(?P<algkey>[a-z0-9]{32})\b|'
    r'algolia.{0,16}(?P<algid>[A-Z0-9]{10})\b|'
    r'cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}(?P<cfapi>[a-z0-9_-]{38,42})\b|'
    r'(?:cloudflare|x-auth-user-service-key).{0,64}(?P<cfsvc>v1\.0-[a-z0-9._-]{160,})\b|'
    r'(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}(?P<segkey>[A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})|'
    r'(?:facebook|fb).{0,8}(?:app|application).{0,16}(?P<fbapp>\d{15})\b|'
    r'(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}(?P<fbsec>[a-z0-9]{32})\b'
    r')',
    re.IGNORECASE
)

# Email pattern
_EMAIL_PAT = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns
_FILE_PAT = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx?|json|xml|ya?ml|'
    r'txt|log|conf(?:ig)?|cfg|ini|env|'
    r'bak|backup|old|orig|copy|'
    r'key|pem|crt|cer|p12|pfx|'
    r'docx?|pdf|'
    r'zip|tar|gz|rar|7z|'
    r'sh|bat|ps1|py|rb|pl'
    r'))["\']',
    re.IGNORECASE
)

# Combined noise pattern - single check instead of loop
_NOISE_PAT = re.compile(
    r'^(?:'
    r'\.\.?/|'
    r'[a-z]{2}(?:-[a-z]{2})?(?:\.js)?$|'
    r'.*-xform$|'
    r'sha\d*$|'
    r'(?:aes|des|md5)$|'
    r'/[A-Z][a-z]+\s?$|'
    r'\d+ \d+ R$|'
    r'(?:xl|docProps|_rels|META-INF|worksheets|theme)/|'
    r'.*\.xml$|'
    r'webpack|'
    r'zone\.js$|'
    r'(?:readable-stream|process|stream)/|'
    r'(?:buffer|events|util|path)$|'
    r'\+|'
    r'\$\{|'
    r'#|'
    r'\?\ref=|'
    r'/[a-zA-Z]$|'
    r'http://$|'
    r'.*_ngcontent'
    r')'
)

# Noise strings - frozenset for O(1)
_NOISE_STRS = frozenset((
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
))

# Noise domains - frozenset for O(1)
_NOISE_DOMS = frozenset((
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
))

# Static extensions - tuple for endswith()
_STATIC_EXT = ('.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf')

# Invalid email domains - frozenset
_BAD_EMAIL_DOMS = frozenset(('example.com', 'test.com', 'domain.com', 'placeholder.com'))

# Pre-compute marker sets for early-exit
_ENDPOINT_MARKERS = frozenset(('"/api', "'/api", '"/v1', "'/v1", '"/v2', "'/v2", 
                                '"/rest', "'/rest", '"/graphql', "'/graphql",
                                '"/auth', "'/auth", '"/login', "'/login",
                                '"/admin', "'/admin", '"/token', "'/token",
                                '"/oauth', "'/oauth", '"/dashboard', "'/dashboard",
                                '"/upload', "'/upload", '"/download', "'/download",
                                '"/config', "'/config", '"/debug', "'/debug",
                                '"/internal', "'/internal", '"/backup', "'/backup",
                                '"/private', "'/private", '"/idp', "'/idp",
                                '"/.well-known', "'/.well-known"))


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer with deep optimizations."""
    __slots__ = ('_callbacks', '_helpers', '_stdout', '_stderr', 
                 'all_findings', 'seen_values', 'panel')
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        self.all_findings = []
        self.seen_values = set()
        
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._log("JS Analyzer loaded - Right-click JS responses to analyze")
    
    def _log(self, msg):
        self._stdout.println("[JS Analyzer] " + str(msg))
    
    def getTabCaption(self):
        return "JS Analyzer"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem("Analyze JS with JS Analyzer")
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu
    
    def analyze_response(self, message_info):
        """Analyze a response - deep optimized."""
        response = message_info.getResponse()
        if not response:
            return
        
        # Get source URL
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            slash_pos = url.rfind('/')
            if slash_pos >= 0:
                source_name = url[slash_pos + 1:].split('?')[0]
            else:
                source_name = url
            if len(source_name) > 40:
                source_name = source_name[:40] + "..."
        except:
            source_name = "Unknown"
        
        # Get response body
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])
        
        body_len = len(body)
        if body_len < 50:
            return
        
        self._log("Analyzing: " + source_name)
        
        # Local refs for speed
        seen = self.seen_values
        all_finds = self.all_findings
        new_finds = []
        
        # Pre-compute lowercase body ONCE for all case-insensitive checks
        body_lower = body.lower()
        
        # ===== 1. ENDPOINTS (with early-exit) =====
        # Quick marker check before regex
        has_endpoint_markers = False
        for marker in _ENDPOINT_MARKERS:
            if marker in body:
                has_endpoint_markers = True
                break
        
        if has_endpoint_markers:
            for m in _ENDPOINT_PAT.findall(body):
                v = m.strip() if m else None
                if v and self._valid_endpoint(v):
                    k = "endpoints:" + v
                    if k not in seen:
                        seen.add(k)
                        f = ("endpoints", v, source_name)
                        all_finds.append(f)
                        new_finds.append(f)
        
        # ===== 2. URLS (with early-exit) =====
        # Quick check for URL markers
        if 'http' in body_lower or 'wss' in body_lower or 'sftp' in body_lower:
            for m in _URL_PAT.finditer(body):
                v = m.group('u1') or m.group('u2') or m.group('u3') or \
                    m.group('s3') or m.group('az') or m.group('gc')
                if v:
                    v = v.strip()
                    if self._valid_url(v, v.lower()):
                        k = "urls:" + v
                        if k not in seen:
                            seen.add(k)
                            f = ("urls", v, source_name)
                            all_finds.append(f)
                            new_finds.append(f)
        
        # ===== 3. SECRETS =====
        # Case-sensitive secrets first (faster)
        for m in _SECRET_PAT.finditer(body):
            v = None
            for gname in ('aws', 'gapi', 'stripe', 'ghpat', 'slack', 'jwt', 
                          'pkey', 'mongo', 'pg', 'mysql', 'segpub', 'fbtok', 'goauth'):
                v = m.group(gname)
                if v:
                    break
            if v and self._valid_secret(v, v.lower()):
                masked = v[:10] + "..." + v[-4:] if len(v) > 20 else v
                k = "secrets:" + masked
                if k not in seen:
                    seen.add(k)
                    f = ("secrets", masked, source_name)
                    all_finds.append(f)
                    new_finds.append(f)
        
        # Case-insensitive secrets (only if markers present)
        if 'algolia' in body_lower or 'cloudflare' in body_lower or \
           'segment' in body_lower or 'facebook' in body_lower or 'fb' in body_lower:
            for m in _SECRET_CI_PAT.finditer(body):
                v = None
                for gname in ('algkey', 'algid', 'cfapi', 'cfsvc', 'segkey', 'fbapp', 'fbsec'):
                    v = m.group(gname)
                    if v:
                        break
                if v and self._valid_secret(v, v.lower()):
                    masked = v[:10] + "..." + v[-4:] if len(v) > 20 else v
                    k = "secrets:" + masked
                    if k not in seen:
                        seen.add(k)
                        f = ("secrets", masked, source_name)
                        all_finds.append(f)
                        new_finds.append(f)
        
        # ===== 4. EMAILS (with early-exit) =====
        if '@' in body:
            for m in _EMAIL_PAT.findall(body):
                v = m.strip() if m else None
                if v and self._valid_email(v, v.lower()):
                    k = "emails:" + v
                    if k not in seen:
                        seen.add(k)
                        f = ("emails", v, source_name)
                        all_finds.append(f)
                        new_finds.append(f)
        
        # ===== 5. FILES (with early-exit) =====
        # Check for common file extension markers
        if '.sql' in body_lower or '.csv' in body_lower or '.json' in body_lower or \
           '.xml' in body_lower or '.yaml' in body_lower or '.log' in body_lower or \
           '.bak' in body_lower or '.key' in body_lower or '.pem' in body_lower or \
           '.pdf' in body_lower or '.zip' in body_lower or '.sh' in body_lower:
            for m in _FILE_PAT.findall(body):
                v = m.strip() if m else None
                if v and self._valid_file(v, v.lower()):
                    k = "files:" + v
                    if k not in seen:
                        seen.add(k)
                        f = ("files", v, source_name)
                        all_finds.append(f)
                        new_finds.append(f)
        
        # Update UI
        if new_finds:
            self._log("Found %d new items" % len(new_finds))
            # Convert tuples to dicts for UI
            findings_for_ui = [{"category": f[0], "value": f[1], "source": f[2]} 
                              for f in new_finds]
            self.panel.add_findings(findings_for_ui, source_name)
        else:
            self._log("No new findings")
    
    def _valid_endpoint(self, v):
        """Validate endpoint - ordered cheapest to most expensive."""
        vlen = len(v)
        if vlen < 3:
            return False
        if v in _NOISE_STRS:
            return False
        if v[0] != '/':
            return False
        # Check parts
        parts = v.split('/')
        if len(parts) < 2:
            return False
        # At least one meaningful segment
        for p in parts:
            if p and len(p) >= 2:
                # Now run expensive noise check
                if _NOISE_PAT.search(v):
                    return False
                return True
        return False
    
    def _valid_url(self, v, vl):
        """Validate URL - vl is pre-lowered."""
        if len(v) < 15:
            return False
        # Noise domain check
        for d in _NOISE_DOMS:
            if d in vl:
                return False
        # Placeholder check
        if '{' in v:
            return False
        if 'undefined' in vl or 'null' in vl:
            return False
        # Data URI
        if vl[0] == 'd' and vl.startswith('data:'):
            return False
        # Static
        if vl.endswith(_STATIC_EXT):
            return False
        return True
    
    def _valid_secret(self, v, vl):
        """Validate secret - vl is pre-lowered."""
        if len(v) < 10:
            return False
        if 'example' in vl or 'placeholder' in vl or 'your' in vl or \
           'xxxx' in vl or 'test' in vl:
            return False
        return True
    
    def _valid_email(self, v, vl):
        """Validate email - vl is pre-lowered."""
        at_pos = vl.rfind('@')
        if at_pos < 1:
            return False
        domain = vl[at_pos + 1:]
        if domain in _BAD_EMAIL_DOMS:
            return False
        if 'example' in vl or 'test' in vl or 'placeholder' in vl or 'noreply' in vl:
            return False
        return True
    
    def _valid_file(self, v, vl):
        """Validate file - vl is pre-lowered."""
        if len(v) < 3:
            return False
        # Common noise
        if 'package.json' in vl or 'tsconfig' in vl or 'webpack' in vl or \
           'babel' in vl or 'eslint' in vl or 'prettier' in vl or \
           'node_modules' in vl or '.min.' in vl or 'polyfill' in vl or \
           'vendor' in vl or 'chunk' in vl or 'bundle' in vl:
            return False
        if vl.endswith('.map'):
            return False
        # Skip short json files (locale)
        if vl.endswith('.json'):
            slash = v.rfind('/')
            basename = v[slash + 1:] if slash >= 0 else v
            if len(basename) <= 7:
                return False
        return True
    
    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
    
    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    __slots__ = ('extender', 'invocation')
    
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        for msg in messages:
            self.extender.analyze_response(msg)
