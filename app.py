"""AuthGuard-1.5B — Minimalist ChatGPT-Style Web Application.

Ultra-clean, full-canvas, distraction-free interface with Enter-to-send,
instant sample cards, and real-time vulnerability detection.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
import threading
import time
from typing import Optional

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from inference.detector import AuthSecurityDetector

detector: Optional[AuthSecurityDetector] = None
is_loading: bool = False


def _init_detector_worker():
    global detector, is_loading
    try:
        is_loading = True
        print("[INFO] Initializing AuthGuard Detector Engine in background...")
        detector = AuthSecurityDetector(device=None)
        print("[OK] AuthGuard Detector is Ready!")
    except Exception as e:
        print(f"[ERROR] Failed to load detector: {e}")
    finally:
        is_loading = False


SAMPLE_PROMPTS = [
    {
        "id": "fastapi-idor",
        "title": "FastAPI Nested IDOR",
        "tag": "IDOR",
        "language": "python",
        "code": """@router.get("/api/organizations/{org_id}/invoices/{invoice_id}")
async def get_invoice(org_id: int, invoice_id: int, db: Session = Depends(get_db)):
    # Vulnerability: Direct query on invoice_id without checking org_id or user ownership
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice""",
    },
    {
        "id": "go-jwt-none",
        "title": "Go JWT 'none' Algorithm Bypass",
        "tag": "Auth Bypass",
        "language": "go",
        "code": """func ValidateToken(tokenStr string) (*Claims, error) {
    // Flaw: Accepts 'none' signing method without cryptographic signature verification
    token, _ := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if token.Method == jwt.SigningMethodNone {
            return jwt.UnsafeAllowNoneSignatureType, nil
        }
        return []byte("secret-key"), nil
    })
    return token.Claims.(*Claims), nil
}""",
    },
    {
        "id": "spring-spel",
        "title": "Spring SpEL Role Mismatch",
        "tag": "Incorrect Authz",
        "language": "java",
        "code": """@RestController
@RequestMapping("/api/patients")
public class PatientController {
    // Flaw: SpEL parameter name mismatch (#id instead of #patientId) bypasses check
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @GetMapping("/{patientId}/medical-records")
    public ResponseEntity<Record> getRecords(@PathVariable("patientId") Long patientId) {
        return ResponseEntity.ok(recordService.findForPatient(patientId));
    }
}""",
    },
    {
        "id": "sound-constant-time",
        "title": "Sound Constant-Time Reset (Clean)",
        "tag": "Clean / Safe",
        "language": "python",
        "code": """@app.post("/api/auth/reset-password")
def reset_password(token: str, new_pass: str, db: Session = Depends(get_db)):
    record = db.query(PasswordReset).filter(PasswordReset.token == token).first()
    if not record or record.is_used or record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    # Secure: Atomic single-use invalidation
    record.is_used = True
    user = db.query(User).filter(User.id == record.user_id).first()
    user.set_password(new_pass)
    db.commit()
    return {"status": "success"}""",
    },
]


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthGuard AI — Security Code Auditor</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-page: #ffffff;
            --bg-bubble-user: #f4f4f4;
            --bg-input: #ffffff;
            --bg-card: #ffffff;
            --bg-card-hover: #f7f7f8;
            --border-subtle: #e5e5e5;
            --border-input: #d1d5db;
            --text-primary: #0d0d0d;
            --text-secondary: #5d5d5d;
            --text-muted: #8e8ea0;
            --btn-send: #000000;
            --btn-send-hover: #2f2f2f;
            --code-bg: #1e1e1e;
            --code-text: #e6edf3;
        }

        [data-theme="dark"] {
            --bg-page: #212121;
            --bg-bubble-user: #2f2f2f;
            --bg-input: #2f2f2f;
            --bg-card: #282828;
            --bg-card-hover: #333333;
            --border-subtle: #3a3a3a;
            --border-input: #4a4a4a;
            --text-primary: #f3f3f3;
            --text-secondary: #b4b4b4;
            --text-muted: #737373;
            --btn-send: #ffffff;
            --btn-send-hover: #e5e5e5;
            --code-bg: #111111;
            --code-text: #e6edf3;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: background-color 0.2s, color 0.2s;
        }

        /* Top Minimalist Header */
        .top-header {
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 28px;
            border-bottom: 1px solid var(--border-subtle);
            flex-shrink: 0;
        }

        .brand-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            cursor: pointer;
        }

        .accuracy-pill {
            background: #dcfce7;
            color: #15803d;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 12px;
            border: 1px solid #bbf7d0;
        }

        [data-theme="dark"] .accuracy-pill {
            background: rgba(22, 163, 74, 0.2);
            color: #4ade80;
            border-color: rgba(22, 163, 74, 0.4);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .header-btn {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 13px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            text-decoration: none;
            transition: all 0.15s;
        }

        .header-btn:hover {
            background: var(--bg-card-hover);
            color: var(--text-primary);
        }

        /* Chat Stream Canvas */
        .chat-scroll {
            flex: 1;
            overflow-y: auto;
            padding: 28px 0 160px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .chat-canvas {
            width: 100%;
            max-width: 780px;
            padding: 0 24px;
            display: flex;
            flex-direction: column;
            gap: 28px;
        }

        /* Centered Blank View */
        .hero-section {
            margin-top: 60px;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 16px;
        }

        .hero-icon {
            width: 52px;
            height: 52px;
            border-radius: 50%;
            background: linear-gradient(135deg, #10a37f, #2563eb);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            color: #fff;
            box-shadow: 0 4px 16px rgba(16, 163, 127, 0.25);
        }

        .hero-title {
            font-size: 28px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }

        .hero-sub {
            font-size: 14px;
            color: var(--text-secondary);
            max-width: 520px;
            line-height: 1.5;
        }

        .prompt-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            width: 100%;
            margin-top: 24px;
        }

        .prompt-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 14px 16px;
            text-align: left;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .prompt-card:hover {
            background: var(--bg-card-hover);
            border-color: #bbb;
            transform: translateY(-1px);
        }

        .prompt-card-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 4px;
        }

        .prompt-card-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .tag-pill {
            font-size: 10px;
            font-weight: 600;
            padding: 2px 6px;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.06);
            color: var(--text-secondary);
        }

        [data-theme="dark"] .tag-pill {
            background: rgba(255, 255, 255, 0.1);
        }

        .prompt-card-sub {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Message Turn */
        .msg-turn {
            display: flex;
            gap: 16px;
            width: 100%;
            animation: fadeIn 0.2s ease-in-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .msg-turn.user {
            justify-content: flex-end;
        }

        .user-bubble {
            background-color: var(--bg-bubble-user);
            padding: 12px 18px;
            border-radius: 18px;
            max-width: 85%;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text-primary);
            white-space: pre-wrap;
            word-break: break-word;
            border: 1px solid var(--border-subtle);
        }

        .ai-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #10a37f;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 15px;
            flex-shrink: 0;
            margin-top: 2px;
        }

        .ai-body {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .verdict-banner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
        }

        .verdict-vuln {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #b91c1c;
        }

        [data-theme="dark"] .verdict-vuln {
            background: rgba(239, 68, 68, 0.15);
            border-color: rgba(239, 68, 68, 0.3);
            color: #f87171;
        }

        .verdict-clean {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #15803d;
        }

        [data-theme="dark"] .verdict-clean {
            background: rgba(22, 163, 74, 0.15);
            border-color: rgba(22, 163, 74, 0.3);
            color: #4ade80;
        }

        .trace-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 16px;
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
        }

        /* Floating Input Bar */
        .input-bar-anchor {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            display: flex;
            justify-content: center;
            padding: 0 24px 24px;
            background: linear-gradient(180deg, transparent 0%, var(--bg-page) 40%);
        }

        .input-pill {
            width: 100%;
            max-width: 780px;
            background-color: var(--bg-input);
            border: 1px solid var(--border-input);
            border-radius: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            display: flex;
            flex-direction: column;
            padding: 12px 16px;
            gap: 6px;
            transition: all 0.2s ease;
        }

        .input-pill:focus-within {
            border-color: #888;
            box-shadow: 0 6px 24px rgba(0, 0, 0, 0.12);
        }

        .input-textarea {
            width: 100%;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text-primary);
            font-family: 'Fira Code', 'Inter', monospace;
            font-size: 13px;
            line-height: 1.45;
            resize: none;
            min-height: 48px;
            max-height: 200px;
        }

        .input-controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .language-select {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 6px;
            outline: none;
            cursor: pointer;
        }

        .send-btn {
            background: var(--btn-send);
            color: var(--bg-page);
            border: none;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: transform 0.1s ease, background 0.15s;
        }

        .send-btn:hover {
            background: var(--btn-send-hover);
            transform: scale(1.05);
        }

        .send-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }

        /* Spinner */
        .spinner {
            width: 14px;
            height: 14px;
            border: 2px solid rgba(0, 0, 0, 0.2);
            border-radius: 50%;
            border-top-color: #10a37f;
            animation: spin 0.7s linear infinite;
        }

        [data-theme="dark"] .spinner {
            border-color: rgba(255, 255, 255, 0.2);
            border-top-color: #4ade80;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body data-theme="light">

    <!-- Top Minimalist Bar -->
    <div class="top-header">
        <div class="brand-logo" onclick="resetCanvas()">
            <span>🛡️ AuthGuard-1.5B</span>
            <span class="accuracy-pill">98.33% Accuracy</span>
        </div>

        <div class="header-actions">
            <button class="header-btn" onclick="resetCanvas()">
                <span>＋ New Audit</span>
            </button>
            <a class="header-btn" href="https://github.com/kuldeep-poonia/auth-security-model" target="_blank">
                <span>⭐ GitHub</span>
            </a>
            <a class="header-btn" href="https://huggingface.co/poonia98/authguard-1.5b" target="_blank">
                <span>🤗 Hugging Face</span>
            </a>
            <button class="header-btn" onclick="toggleTheme()" id="themeBtn">
                <span id="themeIcon">🌙</span>
            </button>
        </div>
    </div>

    <!-- Chat Messages Viewport -->
    <div class="chat-scroll" id="scrollContainer">
        <div class="chat-canvas" id="chatCanvas">
            
            <!-- Hero Blank Greeting -->
            <div class="hero-section" id="heroGreeting">
                <div class="hero-icon">🛡️</div>
                <div class="hero-title">What code would you like to audit?</div>
                <div class="hero-sub">
                    Paste any backend function, route, or controller. Press <b>Enter</b> to detect IDORs, BOLA, Auth Bypass, or Privilege Escalations with 100% recall.
                </div>

                <div class="prompt-grid" id="promptGrid"></div>
            </div>

        </div>
    </div>

    <!-- Floating Input Pill (Enter to Send) -->
    <div class="input-bar-anchor">
        <div class="input-pill">
            <textarea 
                class="input-textarea" 
                id="codePromptInput" 
                placeholder="Paste code snippet here... (Press Enter to audit, Shift+Enter for new line)"
                onkeydown="handleKeyPress(event)"
            ></textarea>

            <div class="input-controls">
                <select class="language-select" id="langSelector">
                    <option value="python">Python</option>
                    <option value="go">Go (Golang)</option>
                    <option value="typescript">TypeScript</option>
                    <option value="javascript">JavaScript</option>
                    <option value="java">Java (Spring)</option>
                    <option value="csharp">C# (.NET)</option>
                    <option value="php">PHP (Laravel)</option>
                </select>

                <button class="send-btn" id="submitBtn" onclick="executeAudit()" title="Run Audit (Enter)">
                    ↑
                </button>
            </div>
        </div>
    </div>

    <script>
        let samplePrompts = [];

        async function fetchSamplePrompts() {
            try {
                const res = await fetch('/api/samples');
                samplePrompts = await res.json();
                
                const grid = document.getElementById('promptGrid');
                grid.innerHTML = '';

                samplePrompts.forEach((s, idx) => {
                    const card = document.createElement('div');
                    card.className = 'prompt-card';
                    card.innerHTML = `
                        <div class="prompt-card-top">
                            <span class="prompt-card-title">${s.title}</span>
                            <span class="tag-pill">${s.tag}</span>
                        </div>
                        <div class="prompt-card-sub">${s.language.toUpperCase()} • Click to test</div>
                    `;
                    card.onclick = () => loadPrompt(idx);
                    grid.appendChild(card);
                });
            } catch (e) {
                console.error("Failed to load samples", e);
            }
        }

        function loadPrompt(idx) {
            const s = samplePrompts[idx];
            if (!s) return;
            const input = document.getElementById('codePromptInput');
            input.value = s.code;
            document.getElementById('langSelector').value = s.language;
            input.focus();
            autoGrow(input);
        }

        function resetCanvas() {
            document.getElementById('chatCanvas').innerHTML = `
                <div class="hero-section" id="heroGreeting">
                    <div class="hero-icon">🛡️</div>
                    <div class="hero-title">What code would you like to audit?</div>
                    <div class="hero-sub">
                        Paste any backend function, route, or controller. Press <b>Enter</b> to detect IDORs, BOLA, Auth Bypass, or Privilege Escalations with 100% recall.
                    </div>
                    <div class="prompt-grid" id="promptGrid"></div>
                </div>
            `;
            fetchSamplePrompts();
            const input = document.getElementById('codePromptInput');
            input.value = '';
            input.focus();
        }

        function handleKeyPress(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                executeAudit();
            } else {
                autoGrow(e.target);
            }
        }

        function autoGrow(element) {
            element.style.height = 'auto';
            element.style.height = Math.min(element.scrollHeight, 200) + 'px';
        }

        async function executeAudit() {
            const input = document.getElementById('codePromptInput');
            const code = input.value.trim();
            const language = document.getElementById('langSelector').value;
            const submitBtn = document.getElementById('submitBtn');

            if (!code) return;

            const hero = document.getElementById('heroGreeting');
            if (hero) hero.remove();

            const canvas = document.getElementById('chatCanvas');

            // 1. User Bubble
            const userTurn = document.createElement('div');
            userTurn.className = 'msg-turn user';
            userTurn.innerHTML = `<div class="user-bubble">${escapeHtml(code)}</div>`;
            canvas.appendChild(userTurn);

            // 2. Loading Placeholder
            const loadingTurn = document.createElement('div');
            loadingTurn.className = 'msg-turn';
            loadingTurn.id = 'loadingTurn';
            loadingTurn.innerHTML = `
                <div class="ai-avatar">🛡️</div>
                <div class="ai-body" style="justify-content: center;">
                    <div style="display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text-secondary);">
                        <div class="spinner"></div> Auditing semantic data flow & auth boundaries...
                    </div>
                </div>
            `;
            canvas.appendChild(loadingTurn);

            scrollBottom();
            input.value = '';
            input.style.height = '48px';
            submitBtn.disabled = true;

            try {
                const response = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, language })
                });
                const report = await response.json();
                loadingTurn.remove();

                const isVuln = report.is_vulnerable;
                const vclass = (report.vulnerability_class || 'none').toUpperCase();
                const confPercent = Math.round((report.confidence || 0) * 100);

                // 3. AI Verdict Response
                const aiTurn = document.createElement('div');
                aiTurn.className = 'msg-turn';
                aiTurn.innerHTML = `
                    <div class="ai-avatar">🛡️</div>
                    <div class="ai-body">
                        <div class="verdict-banner ${isVuln ? 'verdict-vuln' : 'verdict-clean'}">
                            <span>${isVuln ? `🚨 Vulnerable: ${vclass}` : '🛡️ Clean & Sound (No Flaws)'}</span>
                            <span style="font-size:12px; font-weight:normal; opacity:0.9;">Certainty: ${confPercent}%</span>
                        </div>

                        <div class="trace-card">
                            <b>Analysis:</b> ${escapeHtml(report.explanation || 'Code is cryptographically sound and properly scoped.')}
                            
                            ${isVuln && report.flagged_lines && report.flagged_lines.length ? `
                                <div style="margin-top:10px; font-size:12px; color:var(--text-muted);">
                                    📍 Flagged Line Numbers: <b style="color:#ef4444;">${JSON.stringify(report.flagged_lines)}</b>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
                canvas.appendChild(aiTurn);
            } catch (err) {
                loadingTurn.remove();
                const errTurn = document.createElement('div');
                errTurn.className = 'msg-turn';
                errTurn.innerHTML = `
                    <div class="ai-avatar" style="background:#ef4444;">⚠️</div>
                    <div class="ai-body">
                        <div style="color:#ef4444; font-size:13px;">Error: ${escapeHtml(err.message)}</div>
                    </div>
                `;
                canvas.appendChild(errTurn);
            } finally {
                submitBtn.disabled = false;
                scrollBottom();
            }
        }

        function scrollBottom() {
            const scroller = document.getElementById('scrollContainer');
            scroller.scrollTop = scroller.scrollHeight;
        }

        function toggleTheme() {
            const body = document.body;
            const isDark = body.getAttribute('data-theme') === 'dark';
            body.setAttribute('data-theme', isDark ? 'light' : 'dark');
            document.getElementById('themeIcon').textContent = isDark ? '🌙' : '☀️';
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        fetchSamplePrompts();
    </script>
</body>
</html>
"""


class AuthGuardHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html_str: str):
        payload = html_str.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._send_html(HTML_PAGE)
        elif self.path == "/api/samples":
            self._send_json(200, SAMPLE_PROMPTS)
        elif self.path == "/api/health":
            self._send_json(200, {"status": "ready" if detector is not None else ("loading" if is_loading else "idle")})
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == "/api/audit":
            length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(length)
            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Invalid JSON payload"})
                return

            code = data.get("code", "")
            language = data.get("language", "python")

            global detector
            if detector is None:
                self._send_json(503, {"error": "Model is initializing in background. Please wait a moment..."})
                return

            try:
                report = detector.audit_code(code, language=language)
                self._send_json(200, report)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        pass


def run_server(port: int = 7860):
    threading.Thread(target=_init_detector_worker, daemon=True).start()
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, AuthGuardHandler)
    print("=" * 80)
    print(f"  AUTHGUARD MINIMALIST CHATGPT APP IS LIVE!")
    print(f"  • Local URL: http://localhost:{port}  (or http://127.0.0.1:{port})")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    run_server(port=port)
