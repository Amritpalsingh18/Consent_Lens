import os
import re
import io
import json
import hashlib
import threading
from datetime import datetime
from collections import Counter

import streamlit as st
from dotenv import load_dotenv
from pypdf import PdfReader
from google import genai
from flask import Flask, request, jsonify
from werkzeug.serving import make_server

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY", "")
MODEL_NAME = os.getenv("GEMMA_MODEL", "gemma-4-26b-a4b-it")
PAIRING_TOKEN = os.getenv("CONSENT_LENS_TOKEN", "change-this-local-token")

st.set_page_config(
    page_title="CONSENT LENS | Data Trust",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ------------------------------------------------------------
# LOCAL EXTENSION API
# Chrome extension sends permission/activity snapshots here.
# ------------------------------------------------------------

api = Flask("consent_lens_api")
browser_data = {
    "sites": [],
    "updated_at": None,
}
browser_lock = threading.Lock()


@api.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


@api.route("/permissions", methods=["POST"])
def receive_permissions():
    token = request.headers.get("X-Consent-Token", "")
    if token != PAIRING_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    sites = payload.get("sites", [])

    if not isinstance(sites, list):
        return jsonify({"error": "sites must be a list"}), 400

    with browser_lock:
        browser_data["sites"] = sites[:500]
        browser_data["updated_at"] = datetime.now().isoformat()

    return jsonify({"ok": True, "received": len(sites)})


@api.route("/permissions", methods=["GET"])
def get_permissions():
    token = request.headers.get("X-Consent-Token", "")
    if token != PAIRING_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    with browser_lock:
        return jsonify(browser_data)


class LocalAPIServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 8765, api)
        self.ctx = api.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()


if "api_started" not in st.session_state:
    try:
        LocalAPIServer().start()
        st.session_state.api_started = True
    except OSError:
        st.session_state.api_started = False

# ------------------------------------------------------------
# SESSION STATE
# ------------------------------------------------------------

DEFAULTS = {
    "scan_results": [],
    "input_text": "",
    "redacted_text": "",
    "gemma_analysis": "",
    "impact_analysis": "",
    "incident_plan": "",
    "integrity_records": {},
    "security_checklist": {},
    "permission_sites": [],
    "permission_updated": None,
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ------------------------------------------------------------
# LOCAL DATA TOOLS
# ------------------------------------------------------------

PATTERNS = {
    "Email address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "Phone number": r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)",
    "Possible Aadhaar number": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "Possible card number": r"\b(?:\d[ -]*?){13,19}\b",
    "Possible API key/token": r"\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{20,})\b",
    "Possible password assignment": r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}",
    "IP address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


def scan_sensitive_data(text):
    found = []
    for label, pattern in PATTERNS.items():
        for match in re.findall(pattern, text):
            found.append({"type": label, "value": match})

    merged = Counter((x["type"], x["value"]) for x in found)
    return [
        {"type": kind, "value": value, "count": count}
        for (kind, value), count in merged.items()
    ]


def redact_sensitive_data(text):
    for label, pattern in PATTERNS.items():
        text = re.sub(pattern, f"[REDACTED: {label}]", text)
    return text


def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()


def extract_text(upload):
    if not upload:
        return ""

    if upload.name.lower().endswith(".txt"):
        return upload.getvalue().decode("utf-8", errors="ignore")

    if upload.name.lower().endswith(".pdf"):
        try:
            reader = PdfReader(upload)
            return "\n\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as exc:
            return f"PDF extraction failed: {exc}"

    return ""


def gemma(prompt):
    if not API_KEY:
        return "Gemma API key is missing. Add GEMINI_API_KEY to .env."

    try:
        client = genai.Client(api_key=API_KEY)
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
        )
        return response.text or "No response returned."
    except Exception as exc:
        return f"Gemma request failed: {exc}"


def security_prompt(text):
    return f"""
You are CONSENT LENS, a defensive data-security analyst.
Analyze the input using plain language.
Do not claim a breach occurred unless evidence says so.
Do not reproduce secrets or credentials.
Distinguish facts, assumptions, and potential risks.
Give defensive remediation and explain social implications.

Return:
1. Executive summary
2. Potential exposure findings
3. Severity and reasoning
4. Defensive remediation
5. Social implications
6. What requires human verification

INPUT:
{text[:18000]}
"""


def impact_prompt(text):
    return f"""
Analyze the potential social implications of this data-security scenario.
Do not assume harm occurred.
Consider privacy, autonomy, discrimination, vulnerable groups,
financial harm, reputation, trust, consent, and accessibility.
For each concern, explain who may be affected and how to mitigate it.

SCENARIO:
{text[:18000]}
"""


def incident_prompt(text):
    return f"""
Create a defensive incident response plan.
Include containment, evidence preservation, scope, affected people,
internal escalation, legal/privacy professional considerations,
communication, recovery, monitoring, and lessons learned.
Do not advise concealing an incident or deleting evidence.
Do not invent facts.

INCIDENT:
{text[:14000]}
"""


# ------------------------------------------------------------
# LIGHT THEME
# ------------------------------------------------------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&display=swap');

    :root {
        --bg:#f8f7f3;
        --panel:#ffffff;
        --text:#202b3c;
        --muted:#697586;
        --line:#e5e8ed;
        --blue:#335eea;
        --teal:#168a83;
        --amber:#b86b13;
        --red:#c43d4f;
    }

    html,body,[class*="css"] {
        font-family:'DM Sans',sans-serif;
        color:var(--text);
    }

    .stApp { background:var(--bg); }
    .block-container {
        max-width:1400px;
        padding-top:1.5rem;
        padding-bottom:4rem;
    }

    [data-testid="stSidebar"] { display:none; }

    h1,h2,h3 { color:#202b3c!important; }
    p,label,li { font-size:16px; }

    .hero {
        padding:32px;
        border:1px solid #e4e8ef;
        border-radius:24px;
        background:linear-gradient(115deg,#ffffff,#f1f6ff);
        margin-bottom:24px;
    }

    .hero-title {
        font-size:clamp(34px,4vw,52px);
        line-height:1.08;
        font-weight:800;
        letter-spacing:-.04em;
        color:#1c2a40;
    }

    .hero-title span { color:var(--blue); }
    .hero-copy {
        max-width:760px;
        color:#617087;
        font-size:17px;
        line-height:1.65;
        margin-top:12px;
    }

    .eyebrow {
        color:var(--teal);
        font-size:12px;
        font-weight:800;
        letter-spacing:.12em;
        text-transform:uppercase;
        margin-bottom:10px;
    }

    .card {
        background:#fff;
        border:1px solid var(--line);
        border-radius:18px;
        padding:22px;
        box-shadow:0 6px 20px rgba(25,42,70,.035);
        height:100%;
    }

    .metric-label {
        color:#778396;
        font-size:12px;
        font-weight:700;
        letter-spacing:.07em;
        text-transform:uppercase;
    }

    .metric-value {
        font-size:32px;
        font-weight:800;
        margin-top:8px;
        color:#1f2d42;
    }

    .metric-sub {
        color:#758195;
        font-size:14px;
        margin-top:5px;
    }

    .section-copy {
        color:#6c7889;
        font-size:16px;
        margin-bottom:20px;
        line-height:1.6;
    }

    .notice {
        border:1px solid #dbe6fa;
        border-radius:14px;
        padding:16px;
        background:#f1f6ff;
        color:#385274;
        line-height:1.65;
        font-size:15px;
    }

    .warning {
        border:1px solid #f2dfc1;
        border-radius:14px;
        padding:16px;
        background:#fff8ed;
        color:#80531e;
        line-height:1.65;
        font-size:15px;
    }

    .stButton>button {
        border-radius:12px;
        min-height:46px;
        font-weight:700;
        border:1px solid #d9e1ee;
        background:#fff;
        color:#26364e;
    }

    .stButton>button[kind="primary"] {
        background:#335eea;
        border-color:#335eea;
        color:white;
    }

    .stTextArea textarea,.stTextInput input {
        background:#fff!important;
        color:#202b3c!important;
        border:1px solid #dfe4ec!important;
        border-radius:12px!important;
        font-size:16px!important;
    }

    [data-testid="stFileUploader"] {
        border:1px dashed #cfd8e6;
        border-radius:14px;
        background:#fff;
        padding:10px;
    }

    [data-testid="stMetric"] {
        background:#fff;
        border:1px solid #e5e8ed;
        padding:18px;
        border-radius:16px;
    }

    #MainMenu,footer { visibility:hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------
# TOP NAVIGATION — NO SIDEBAR
# ------------------------------------------------------------

st.markdown(
    """
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
      <div style="font-size:30px;color:#335eea;font-weight:900;">◈</div>
      <div>
        <div style="font-size:22px;font-weight:800;color:#202b3c;">CONSENT LENS</div>
        <div style="font-size:13px;color:#778396;">Data Trust · Security · Privacy · Social Impact</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

page = st.radio(
    "Dashboard navigation",
    [
        "Overview",
        "Protect Data",
        "Privacy & Permissions",
        "Impact & Response",
    ],
    horizontal=True,
    label_visibility="collapsed",
)

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Your data trust workspace</div>
      <div class="hero-title">Protect the data.<br><span>Preserve the truth.</span></div>
      <div class="hero-copy">
        Scan sensitive information, verify file integrity, review website permissions,
        and make security decisions with people and privacy in mind.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------
# OVERVIEW
# ------------------------------------------------------------

if page == "Overview":
    total_findings = len(st.session_state.scan_results)
    integrity_count = len(st.session_state.integrity_records)

    cols = st.columns(4)
    metrics = [
        ("Potential findings", total_findings, "Local scan results"),
        ("Integrity records", integrity_count, "SHA-256 fingerprints"),
        ("Browser sites", len(st.session_state.permission_sites), "Extension-reported sites"),
        ("AI model", "Gemma", MODEL_NAME),
    ]

    for col, (label, value, sub) in zip(cols, metrics):
        with col:
            st.markdown(
                f"""
                <div class="card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                    <div class="metric-sub">{sub}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("### Start with a task")
    c1, c2, c3, c4 = st.columns(4)
    actions = [
        ("Protect Data", "Scan and redact sensitive data"),
        ("Privacy & Permissions", "Review browser permissions"),
        ("Impact & Response", "Assess social impact or respond"),
        ("Protect Data", "Verify file integrity"),
    ]

    for col, (target, description) in zip([c1, c2, c3, c4], actions):
        with col:
            st.markdown(f"<div class='card'><b>{target}</b><p>{description}</p></div>",
                        unsafe_allow_html=True)

    st.markdown("### Quick scan")
    quick_text = st.text_area(
        "Paste text you are authorized to review",
        height=140,
        key="overview_quick_scan",
    )

    if st.button("Run local scan", type="primary"):
        st.session_state.scan_results = scan_sensitive_data(quick_text)
        st.session_state.input_text = quick_text
        st.success(f"Scan complete. {len(st.session_state.scan_results)} potential finding(s).")


# ------------------------------------------------------------
# PROTECT DATA
# ------------------------------------------------------------

elif page == "Protect Data":
    st.markdown("## Protect Data")
    st.markdown(
        '<div class="section-copy">Local scanning, redaction, file integrity, and Gemma-powered analysis.</div>',
        unsafe_allow_html=True,
    )

    tool = st.selectbox(
        "Choose a tool",
        [
            "Sensitive Data Scanner",
            "Privacy Shield",
            "Integrity Vault",
            "Gemma Security Analyst",
        ],
    )

    if tool == "Sensitive Data Scanner":
        uploaded = st.file_uploader("Upload TXT or text-based PDF", type=["txt", "pdf"])
        source = extract_text(uploaded) if uploaded else ""
        text = st.text_area("Text to scan", value=source or st.session_state.input_text, height=230)

        if st.button("Scan locally", type="primary"):
            st.session_state.input_text = text
            st.session_state.scan_results = scan_sensitive_data(text)

        if st.session_state.scan_results:
            st.metric("Potential findings", len(st.session_state.scan_results))
            st.dataframe(st.session_state.scan_results, use_container_width=True)

            st.warning(
                "Pattern-based detection can produce false positives and false negatives. "
                "Findings do not prove a breach."
            )

    elif tool == "Privacy Shield":
        text = st.text_area(
            "Text to redact",
            value=st.session_state.input_text,
            height=230,
        )

        if st.button("Redact sensitive patterns", type="primary"):
            st.session_state.redacted_text = redact_sensitive_data(text)

        if st.session_state.redacted_text:
            st.text_area("Redacted preview", st.session_state.redacted_text, height=220)
            st.download_button(
                "Download redacted text",
                st.session_state.redacted_text,
                "redacted_data.txt",
                mime="text/plain",
            )

    elif tool == "Integrity Vault":
        uploaded = st.file_uploader("Choose a file to fingerprint", key="integrity_upload")

        if uploaded:
            raw = uploaded.getvalue()
            digest = calculate_sha256(raw)
            st.markdown("### SHA-256 fingerprint")
            st.code(digest)
            st.write(f"Filename: {uploaded.name}")
            st.write(f"Size: {len(raw):,} bytes")

            if st.button("Save integrity record", type="primary"):
                st.session_state.integrity_records[uploaded.name] = digest
                st.success("Saved for this Streamlit session.")

            if uploaded.name in st.session_state.integrity_records:
                previous = st.session_state.integrity_records[uploaded.name]
                if previous == digest:
                    st.success("File matches the saved fingerprint.")
                else:
                    st.error("File differs from the saved fingerprint.")

        if st.session_state.integrity_records:
            st.json(st.session_state.integrity_records)
            st.download_button(
                "Export integrity records",
                json.dumps(st.session_state.integrity_records, indent=2),
                "integrity_records.json",
                mime="application/json",
            )

    elif tool == "Gemma Security Analyst":
        text = st.text_area(
            "Security scenario or redacted text",
            value=st.session_state.redacted_text or st.session_state.input_text,
            height=230,
        )

        st.warning("Avoid sending passwords, tokens, private keys, or unnecessary personal data to an AI API.")

        if st.button("Analyze with Gemma", type="primary"):
            if not text.strip():
                st.warning("Enter a scenario first.")
            else:
                with st.spinner("Gemma is analyzing..."):
                    st.session_state.gemma_analysis = gemma(security_prompt(text))

        if st.session_state.gemma_analysis:
            st.markdown(st.session_state.gemma_analysis)


# ------------------------------------------------------------
# PRIVACY & PERMISSIONS
# ------------------------------------------------------------

elif page == "Privacy & Permissions":
    st.markdown("## Privacy & Permissions")
    st.markdown(
        '<div class="section-copy">Review website permissions and identify sites that may no longer need access.</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="notice">
        Browser permissions are inspected by the companion Chrome extension.
        Streamlit alone cannot access or revoke permissions for arbitrary websites.
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Connect the browser extension")
    st.markdown(
        """
        1. Install the CONSENT LENS extension from your local `browser_extension` folder.
        2. Open its popup and press **Sync permissions**.
        3. Return here and click **Refresh browser data**.
        """
    )

    if st.button("Refresh browser data"):
        try:
            import requests
            response = requests.get(
                "http://127.0.0.1:8765/permissions",
                headers={"X-Consent-Token": PAIRING_TOKEN},
                timeout=3,
            )
            response.raise_for_status()
            data = response.json()
            st.session_state.permission_sites = data.get("sites", [])
            st.session_state.permission_updated = data.get("updated_at")
            st.success("Browser data refreshed.")
        except Exception as exc:
            st.error(f"Could not connect to extension API: {exc}")

    if st.session_state.permission_updated:
        st.caption(f"Last extension sync: {st.session_state.permission_updated}")

    sites = st.session_state.permission_sites

    if sites:
        flattened = []
        for site in sites:
            for permission in site.get("permissions", []):
                flattened.append({
                    "Website": site.get("domain", "Unknown"),
                    "Permission": permission.get("type", "Unknown"),
                    "Current setting": permission.get("setting", "Unknown"),
                    "Last activity": site.get("last_activity", "Unknown"),
                    "Risk": permission.get("risk", "Review"),
                })

        st.dataframe(flattened, use_container_width=True)

        st.markdown("### Permission risk")
        high = sum(1 for row in flattened if row["Risk"] == "High")
        medium = sum(1 for row in flattened if row["Risk"] == "Medium")
        low = sum(1 for row in flattened if row["Risk"] == "Low")
        a, b, c = st.columns(3)
        a.metric("High risk", high)
        b.metric("Medium risk", medium)
        c.metric("Low risk", low)

        st.markdown("### Revocation policy")
        st.write(
            "The extension can identify permissions eligible for review after 30 days "
            "of inactivity. Automatic blocking should be explicitly enabled in the "
            "extension settings and should use a grace period and exception list."
        )
    else:
        st.info("No extension permission snapshot has been received yet.")

    st.markdown("### What the auditor evaluates")
    st.write(
        "- Permission sensitivity and current setting\n"
        "- Whether a permission appears necessary for the site's purpose\n"
        "- Last recorded site activity\n"
        "- Inactivity-based review eligibility\n"
        "- Unsupported permission types that need manual review"
    )


# ------------------------------------------------------------
# IMPACT & RESPONSE
# ------------------------------------------------------------

elif page == "Impact & Response":
    st.markdown("## Impact & Response")
    st.markdown(
        '<div class="section-copy">Explore potential harm, create response plans, and document security practices.</div>',
        unsafe_allow_html=True,
    )

    tool = st.selectbox(
        "Choose a tool",
        [
            "Social Impact Radar",
            "Incident Response Copilot",
            "Data Trust Checklist",
            "Security Report",
        ],
    )

    if tool == "Social Impact Radar":
        text = st.text_area(
            "Describe the data system or scenario",
            value=st.session_state.input_text,
            height=230,
        )

        if st.button("Assess social impact", type="primary"):
            if not text.strip():
                st.warning("Describe a scenario first.")
            else:
                with st.spinner("Assessing potential impacts..."):
                    st.session_state.impact_analysis = gemma(impact_prompt(text))

        if st.session_state.impact_analysis:
            st.markdown(st.session_state.impact_analysis)

    elif tool == "Incident Response Copilot":
        text = st.text_area("Incident details", height=230)

        if st.button("Create response plan", type="primary"):
            if not text.strip():
                st.warning("Provide incident details first.")
            else:
                with st.spinner("Creating a response plan..."):
                    st.session_state.incident_plan = gemma(incident_prompt(text))

        if st.session_state.incident_plan:
            st.markdown(st.session_state.incident_plan)

    elif tool == "Data Trust Checklist":
        checklist_items = [
            "Access is limited to authorized people",
            "Multi-factor authentication is enabled where available",
            "Sensitive data is encrypted at rest",
            "Sensitive data is encrypted in transit",
            "Backups are maintained and recovery is tested",
            "Data retention and deletion rules are defined",
            "Incident response roles are documented",
            "Security updates are applied regularly",
            "Sensitive data is minimized",
            "Affected people can be informed appropriately",
        ]

        for item in checklist_items:
            st.session_state.security_checklist[item] = st.checkbox(
                item,
                value=st.session_state.security_checklist.get(item, False),
                key=f"check_{item}",
            )

        score = round(
            100 * sum(st.session_state.security_checklist.values()) / len(checklist_items)
        )
        st.metric("Checklist completion", f"{score}%")
        st.progress(score / 100)

        st.caption("Self-assessment only. Not a security audit or certification.")

    elif tool == "Security Report":
        report = [
            "CONSENT LENS — DATA TRUST REPORT",
            f"Generated: {datetime.now().isoformat(timespec='minutes')}",
            "",
            "=== SCAN FINDINGS ===",
            json.dumps(st.session_state.scan_results, indent=2),
            "",
            "=== GEMMA SECURITY ANALYSIS ===",
            st.session_state.gemma_analysis or "Not generated.",
            "",
            "=== SOCIAL IMPACT ===",
            st.session_state.impact_analysis or "Not generated.",
            "",
            "=== INCIDENT RESPONSE ===",
            st.session_state.incident_plan or "Not generated.",
            "",
            "=== INTEGRITY RECORDS ===",
            json.dumps(st.session_state.integrity_records, indent=2),
            "",
            "=== DATA TRUST CHECKLIST ===",
            json.dumps(st.session_state.security_checklist, indent=2),
            "",
            "=== BROWSER PERMISSIONS ===",
            json.dumps(st.session_state.permission_sites, indent=2),
            "",
            "Limitations: pattern scans and AI output require human review. "
            "This report does not establish that a system is secure or compromised.",
        ]

        final_report = "\n".join(report)
        st.text_area("Report preview", final_report, height=400)
        st.download_button(
            "Download report",
            final_report,
            "consent_lens_report.txt",
            mime="text/plain",
            type="primary",
        )

# ------------------------------------------------------------
# FOOTER
# ------------------------------------------------------------

st.markdown(
    """
    <div style="border-top:1px solid #e5e8ed;margin-top:42px;padding-top:18px;color:#8792a2;font-size:13px;">
    CONSENT LENS · Data Security · Integrity · Privacy · Social Impact
    </div>
    """,
    unsafe_allow_html=True,
)