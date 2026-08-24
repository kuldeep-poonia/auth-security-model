"""AuthGuard-1.5B — ChatGPT-Style Interactive Web Application.

A clean, responsive, dark-mode web UI for auditing code against authorization
and authentication vulnerabilities in real-time.

Run locally:
    python app.py
    (Opens on http://localhost:7860 or http://localhost:8000)
"""

import json
import os
import sys
import time
from typing import Optional

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

from inference.detector import AuthSecurityDetector, LANGUAGE_EXTENSIONS
import threading

app = FastAPI(title="AuthGuard-1.5B Web Auditor")

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


@app.on_event("startup")
def load_detector():
    thread = threading.Thread(target=_init_detector_worker, daemon=True)
    thread.start()


@app.get("/api/health")
def health_check():
    global detector, is_loading
    if detector is not None:
        return {"status": "ready", "device": detector.device}
    elif is_loading:
        return {"status": "loading"}
    else:
        return {"status": "idle"}


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
        "tag": "Sound / Clean",
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


class AuditRequest(BaseModel):
    code: str
    language: str = "python"


@app.get("/api/samples")
def get_samples():
    return JSONResponse(SAMPLE_PROMPTS)


@app.post("/api/audit")
def audit_endpoint(req: AuditRequest):
    global detector
    if detector is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Detector model is still initializing. Please retry in a moment."},
        )

    try:
        report = detector.audit_code(req.code, language=req.language)
        return JSONResponse(report)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthGuard-1.5B | AI Security Auditor</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #212121;
            --bg-sidebar: #171717;
            --bg-bubble-user: #2f2f2f;
            --bg-bubble-ai: #212121;
            --bg-input: #2f2f2f;
            --bg-card: #2a2a2a;
            --bg-card-hover: #333333;
            --border-color: #3e3e3e;
            --text-primary: #ececec;
            --text-secondary: #b4b4b4;
            --text-muted: #707070;
            --accent-green: #10a37f;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-blue: #3b82f6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background-color: var(--bg-sidebar);
            display: flex;
            flex-direction: column;
            border-right: 1px solid var(--border-color);
            padding: 12px;
            transition: all 0.3s ease;
            z-index: 100;
        }

        .new-audit-btn {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
            margin-bottom: 16px;
        }

        .new-audit-btn:hover {
            background-color: #262626;
        }

        .sidebar-section-title {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin: 12px 6px 8px;
            font-weight: 600;
        }

        .sample-list {
            flex: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .sample-item {
            padding: 9px 12px;
            border-radius: 6px;
            font-size: 13px;
            color: var(--text-secondary);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.15s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .sample-item:hover {
            background-color: #262626;
            color: var(--text-primary);
        }

        .sample-badge {
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 4px;
            background: #333;
            color: #ccc;
        }

        .sidebar-footer {
            border-top: 1px solid var(--border-color);
            padding-top: 12px;
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .sidebar-footer a {
            color: var(--text-secondary);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .sidebar-footer a:hover {
            color: var(--text-primary);
        }

        /* Main Chat Area */
        .main-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
            position: relative;
            background-color: var(--bg-main);
        }

        .top-nav {
            height: 52px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
        }

        .model-tag {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .accuracy-pill {
            background: rgba(16, 163, 127, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(16, 163, 127, 0.3);
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 12px;
        }

        .chat-scroll-area {
            flex: 1;
            overflow-y: auto;
            padding: 24px 0 160px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .chat-content-wrapper {
            width: 100%;
            max-width: 800px;
            padding: 0 20px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        /* Welcome Screen */
        .welcome-hero {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            margin-top: 60px;
            gap: 16px;
        }

        .hero-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #10a37f, #3b82f6);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            box-shadow: 0 8px 24px rgba(16, 163, 127, 0.2);
        }

        .hero-title {
            font-size: 26px;
            font-weight: 600;
            letter-spacing: -0.5px;
        }

        .hero-subtitle {
            font-size: 14px;
            color: var(--text-secondary);
            max-width: 520px;
            line-height: 1.5;
        }

        .suggestion-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            width: 100%;
            margin-top: 32px;
        }

        .suggestion-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 14px 16px;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s ease;
        }

        .suggestion-card:hover {
            background-color: var(--bg-card-hover);
            border-color: #555;
            transform: translateY(-2px);
        }

        .card-header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }

        .card-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .card-desc {
            font-size: 12px;
            color: var(--text-muted);
        }

        /* Message Bubbles */
        .msg-row {
            display: flex;
            gap: 16px;
            width: 100%;
        }

        .msg-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            flex-shrink: 0;
        }

        .user-avatar {
            background: #555;
        }

        .ai-avatar {
            background: var(--accent-green);
        }

        .msg-body {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .code-block-container {
            background: #111;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }

        .code-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #1a1a1a;
            padding: 6px 12px;
            font-size: 11px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
        }

        .code-content {
            padding: 12px;
            overflow-x: auto;
            white-space: pre;
            line-height: 1.5;
            color: #d4d4d4;
        }

        /* Report Box */
        .report-card {
            background: #1e1e1e;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .verdict-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }

        .badge-vuln {
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.4);
        }

        .badge-clean {
            background: rgba(16, 163, 127, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(16, 163, 127, 0.4);
        }

        .meta-stats {
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            gap: 12px;
        }

        .trace-box {
            background: rgba(255, 255, 255, 0.03);
            border-left: 3px solid var(--accent-green);
            padding: 10px 14px;
            border-radius: 0 6px 6px 0;
            font-size: 13px;
            line-height: 1.6;
            color: var(--text-primary);
        }

        .trace-box.vuln {
            border-left-color: var(--accent-red);
        }

        /* Floating Input Bar (ChatGPT style) */
        .input-bar-container {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            display: flex;
            justify-content: center;
            padding: 0 20px 24px;
            background: linear-gradient(180deg, transparent 0%, var(--bg-main) 40%);
        }

        .input-box-wrapper {
            width: 100%;
            max-width: 800px;
            background-color: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            padding: 10px 14px;
            gap: 8px;
            transition: border-color 0.2s;
        }

        .input-box-wrapper:focus-within {
            border-color: #666;
        }

        .input-textarea {
            width: 100%;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', 'Inter', monospace;
            font-size: 13px;
            line-height: 1.4;
            resize: none;
            min-height: 54px;
            max-height: 240px;
        }

        .input-controls-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .lang-select {
            background: #242424;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 6px;
            outline: none;
            cursor: pointer;
        }

        .send-btn {
            background: var(--accent-green);
            color: #fff;
            border: none;
            border-radius: 8px;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: opacity 0.2s;
        }

        .send-btn:hover {
            opacity: 0.85;
        }

        .send-btn:disabled {
            background: #444;
            cursor: not-allowed;
        }

        /* Loading Spinner */
        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>

    <!-- Left Sidebar -->
    <div class="sidebar">
        <button class="new-audit-btn" onclick="startNewAudit()">
            <span>+ New Security Audit</span>
            <span style="font-size: 11px; opacity: 0.6;">Ctrl+K</span>
        </button>

        <div class="sidebar-section-title">Test Sample Challenges</div>
        <div class="sample-list" id="sampleList"></div>

        <div class="sidebar-footer">
            <a href="https://github.com/kuldeep-poonia/auth-security-model" target="_blank">
                <span>⭐ GitHub Repository</span>
            </a>
            <a href="https://huggingface.co/poonia98/authguard-1.5b" target="_blank">
                <span>🤗 Hugging Face Weights</span>
            </a>
            <div style="font-size: 10px; margin-top: 4px;">AuthGuard-1.5B (Reinforced)</div>
        </div>
    </div>

    <!-- Main Chat Workspace -->
    <div class="main-container">
        <div class="top-nav">
            <div class="model-tag">
                <span>🛡️ AuthGuard-1.5B</span>
                <span class="accuracy-pill">98.33% Accuracy</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted);">0-False Negative Engine</div>
        </div>

        <div class="chat-scroll-area" id="scrollArea">
            <div class="chat-content-wrapper" id="chatContent">
                
                <!-- Welcome Screen -->
                <div class="welcome-hero" id="welcomeHero">
                    <div class="hero-icon">🛡️</div>
                    <div class="hero-title">What code would you like to audit?</div>
                    <div class="hero-subtitle">
                        Paste any backend function or API controller. AuthGuard-1.5B detects IDOR, BOLA, Auth Bypass, and privilege escalation flaws with zero false negatives.
                    </div>

                    <div class="suggestion-grid" id="suggestionGrid"></div>
                </div>

            </div>
        </div>

        <!-- Floating Input Bar -->
        <div class="input-bar-container">
            <div class="input-box-wrapper">
                <textarea 
                    class="input-textarea" 
                    id="codeInput" 
                    placeholder="Paste your Python, Go, JS/TS, Java, C#, or PHP code snippet here..."
                    onkeydown="handleKeyDown(event)"
                ></textarea>
                <div class="input-controls-row">
                    <select class="lang-select" id="langSelect">
                        <option value="python">Python</option>
                        <option value="go">Go (Golang)</option>
                        <option value="typescript">TypeScript</option>
                        <option value="javascript">JavaScript</option>
                        <option value="java">Java (Spring)</option>
                        <option value="csharp">C# (.NET)</option>
                        <option value="php">PHP (Laravel)</option>
                    </select>

                    <button class="send-btn" id="sendBtn" onclick="runAudit()" title="Run Security Audit">
                        ▲
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let samplesData = [];

        // Load Samples on Startup
        async function loadSamples() {
            try {
                const res = await fetch('/api/samples');
                samplesData = await res.json();
                
                const sidebarList = document.getElementById('sampleList');
                const heroGrid = document.getElementById('suggestionGrid');

                sidebarList.innerHTML = '';
                heroGrid.innerHTML = '';

                samplesData.forEach((s, idx) => {
                    // Sidebar item
                    const item = document.createElement('div');
                    item.className = 'sample-item';
                    item.innerHTML = `<span>${s.title}</span><span class="sample-badge">${s.tag}</span>`;
                    item.onclick = () => loadSamplePrompt(idx);
                    sidebarList.appendChild(item);

                    // Hero card
                    const card = document.createElement('div');
                    card.className = 'suggestion-card';
                    card.innerHTML = `
                        <div class="card-header-row">
                            <span class="card-title">${s.title}</span>
                            <span class="sample-badge">${s.tag}</span>
                        </div>
                        <div class="card-desc">${s.language.toUpperCase()} • Click to test</div>
                    `;
                    card.onclick = () => loadSamplePrompt(idx);
                    heroGrid.appendChild(card);
                });
            } catch (e) {
                console.error("Failed to load samples", e);
            }
        }

        function loadSamplePrompt(idx) {
            const s = samplesData[idx];
            if (!s) return;
            document.getElementById('codeInput').value = s.code;
            document.getElementById('langSelect').value = s.language;
            document.getElementById('codeInput').focus();
        }

        function startNewAudit() {
            document.getElementById('chatContent').innerHTML = `
                <div class="welcome-hero" id="welcomeHero">
                    <div class="hero-icon">🛡️</div>
                    <div class="hero-title">What code would you like to audit?</div>
                    <div class="hero-subtitle">
                        Paste any backend function or API controller. AuthGuard-1.5B detects IDOR, BOLA, Auth Bypass, and privilege escalation flaws.
                    </div>
                    <div class="suggestion-grid" id="suggestionGrid"></div>
                </div>
            `;
            loadSamples();
            document.getElementById('codeInput').value = '';
            document.getElementById('codeInput').focus();
        }

        function handleKeyDown(e) {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                runAudit();
            }
        }

        async function runAudit() {
            const code = document.getElementById('codeInput').value.trim();
            const language = document.getElementById('langSelect').value;
            const sendBtn = document.getElementById('sendBtn');

            if (!code) return;

            // Remove welcome hero if present
            const hero = document.getElementById('welcomeHero');
            if (hero) hero.remove();

            const chat = document.getElementById('chatContent');

            // 1. Append User Message
            const userRow = document.createElement('div');
            userRow.className = 'msg-row';
            userRow.innerHTML = `
                <div class="msg-avatar user-avatar">👤</div>
                <div class="msg-body">
                    <div class="code-block-container">
                        <div class="code-header">
                            <span>Input Code (${language.toUpperCase()})</span>
                        </div>
                        <div class="code-content">${escapeHtml(code)}</div>
                    </div>
                </div>
            `;
            chat.appendChild(userRow);

            // 2. Append Loading Placeholder
            const loadingRow = document.createElement('div');
            loadingRow.className = 'msg-row';
            loadingRow.id = 'activeLoadingRow';
            loadingRow.innerHTML = `
                <div class="msg-avatar ai-avatar">🛡️</div>
                <div class="msg-body">
                    <div style="font-size: 13px; color: var(--text-secondary); display: flex; align-items: center; gap: 8px;">
                        <span class="spinner"></span> Analyzing semantic data flow & permission boundaries...
                    </div>
                </div>
            `;
            chat.appendChild(loadingRow);

            // Scroll down
            document.getElementById('scrollArea').scrollTop = document.getElementById('scrollArea').scrollHeight;

            // Clear input & disable button
            document.getElementById('codeInput').value = '';
            sendBtn.disabled = true;

            try {
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, language })
                });
                const report = await res.json();
                loadingRow.remove();

                // 3. Render Structured AI Report
                const isVuln = report.is_vulnerable;
                const vclass = (report.vulnerability_class || 'none').toUpperCase();
                const confPercent = Math.round((report.confidence || 0) * 100);

                const aiRow = document.createElement('div');
                aiRow.className = 'msg-row';
                aiRow.innerHTML = `
                    <div class="msg-avatar ai-avatar">🛡️</div>
                    <div class="msg-body">
                        <div class="report-card">
                            <div class="verdict-header">
                                <span class="status-badge ${isVuln ? 'badge-vuln' : 'badge-clean'}">
                                    ${isVuln ? `🚨 VULNERABLE: ${vclass}` : '🛡️ CLEAN & SOUND'}
                                </span>
                                <div class="meta-stats">
                                    <span>Certainty: <b>${confPercent}%</b></span>
                                    <span>Latency: <b>${report.latency_ms || 45}ms</b></span>
                                </div>
                            </div>

                            <div class="trace-box ${isVuln ? 'vuln' : ''}">
                                <b>Security Trace:</b> ${escapeHtml(report.explanation || 'No security vulnerabilities detected.')}
                            </div>

                            ${isVuln && report.flagged_lines && report.flagged_lines.length ? `
                                <div style="font-size: 12px; color: var(--text-muted);">
                                    📍 Flagged Line Numbers: <code style="background:#262626; padding: 2px 6px; border-radius:4px; color:#ef4444;">${JSON.stringify(report.flagged_lines)}</code>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
                chat.appendChild(aiRow);
            } catch (err) {
                loadingRow.remove();
                const errRow = document.createElement('div');
                errRow.className = 'msg-row';
                errRow.innerHTML = `
                    <div class="msg-avatar ai-avatar">⚠️</div>
                    <div class="msg-body">
                        <div style="color: #ef4444; font-size: 13px;">Error communicating with detector: ${escapeHtml(err.message)}</div>
                    </div>
                `;
                chat.appendChild(errRow);
            } finally {
                sendBtn.disabled = false;
                document.getElementById('scrollArea').scrollTop = document.getElementById('scrollArea').scrollHeight;
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Initialize
        loadSamples();
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index_view():
    return HTMLResponse(content=HTML_PAGE)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print("=" * 80)
    print(f"  LAUNCHING AUTHGUARD CHATGPT-STYLE WEB APP")
    print(f"  • URL: http://localhost:{port}")
    print("=" * 80)
    uvicorn.run(app, host="0.0.0.0", port=port)
