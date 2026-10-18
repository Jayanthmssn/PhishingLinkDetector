
import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="Phishing Link Detector",
    page_icon="🛡️",
    layout="wide"
)

# ---------- URL ANALYSIS ----------
def analyze_url(user_url):
    user_url = user_url.strip()

    if not user_url:
        return "Invalid input", 0, ["Please enter a URL."]

    if any(ch.isspace() for ch in user_url):
        return "Invalid input", 0, ["URL contains spaces."]

    if not re.match(r"^https?://", user_url, re.I):
        user_url = "https://" + user_url

    try:
        parsed = urlparse(user_url)
        domain = parsed.hostname

        if not domain:
            return "Invalid input", 0, ["Domain not found."]

        try:
            domain = domain.encode("idna").decode("ascii")
            parsed.port
        except (UnicodeError, ValueError):
            return "Invalid input", 0, ["Invalid domain or port."]

    except ValueError:
        return "Invalid input", 0, ["Malformed URL."]

    score = 0
    reasons = []

    if len(user_url) > 75:
        score += 1
        reasons.append("The URL is unusually long.")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("The @ symbol may obscure the destination.")

    try:
        ipaddress.ip_address(domain)
        score += 2
        reasons.append("The hostname is an IP address.")
    except ValueError:
        pass

    if domain.count("-") >= 3:
        score += 1
        reasons.append("The domain contains many hyphens.")

    words = [
        "login", "verify", "password", "account",
        "update", "secure", "bank", "free"
    ]

    found = [word for word in words if word in user_url.lower()]

    if found:
        score += 1
        reasons.append("Potentially sensitive words: " + ", ".join(found))

    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("The URL uses HTTP instead of HTTPS.")

    if score >= 3:
        result = "Suspicious indicators detected"
    else:
        result = "No major indicators detected"

    return result, score, reasons


# ---------- DASHBOARD ----------
st.title("🛡️ Phishing Link Detector")
st.caption("Cyber Security Mini Project | URL Risk Analysis")

st.info(
    "This tool checks URL patterns. It does not confirm whether "
    "a website is malicious or safe."
)

# Session-based scan history
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

st.subheader("🔎 Scan a URL")

with st.form("url_form"):
    url = st.text_input(
        "Website URL",
        placeholder="https://example.com"
    )
    submitted = st.form_submit_button(
        "Analyze URL",
        type="primary"
    )

if submitted:
    result, score, reasons = analyze_url(url)

    if result == "Invalid input":
        st.error("Invalid input")
        for reason in reasons:
            st.write("- " + reason)
    else:
        st.session_state.scan_history.insert(
            0,
            {
                "URL": url.strip(),
                "Result": result,
                "Score": score,
                "Indicators": len(reasons)
            }
        )

        st.subheader("📊 Analysis Results")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Risk score", score)

        with col2:
            st.metric("Indicators found", len(reasons))

        with col3:
            st.metric(
                "URL length",
                len(url.strip())
            )

        if score >= 3:
            st.error("⚠️ " + result)
        else:
            st.success("ℹ️ " + result)

        st.write("**Why this result?**")

        if reasons:
            for reason in reasons:
                st.write("- " + reason)
        else:
            st.write("No indicators from the current rules.")

        st.warning(
            "A low score does not mean the website is safe. "
            "This score is a simple heuristic, not a probability."
        )

st.divider()
st.subheader("🧾 Recent Scan History")

if st.session_state.scan_history:
    st.dataframe(
        st.session_state.scan_history,
        use_container_width=True,
        hide_index=True
    )

    if st.button("Clear scan history"):
        st.session_state.scan_history = []
        st.rerun()
else:
    st.write("Your scan history will appear here.")

st.divider()
st.caption(
    "Built with Python and Streamlit | Educational prototype"
)
