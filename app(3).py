import os
import json
import re
import ipaddress
import requests
import streamlit as st

from sources import (
    run_sources,
    is_ip,
    is_url,
    extract_domain
)

st.set_page_config(
    page_title="Cyberlense",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cyberlense")
st.subheader("Intelligent IP, Domain & URL Security Scanner")

def validate_target(target):
    target = target.strip()

    if not target:
        return False, "Please enter an IP address, domain, or URL."

    if is_ip(target):
        return True, "Valid IP address"

    if is_url(target):
        try:
            domain = extract_domain(target)
            if domain:
                return True, "Valid URL"
        except Exception:
            pass
        return False, "Invalid URL."

    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if re.match(domain_pattern, target):
        return True, "Valid domain"

    return False, "Enter a valid IP address, domain, or URL."


def calculate_risk(source_results):

    vt = source_results.get("VirusTotal", {})
    whois_result = source_results.get("WHOIS", {})

    vt_data = vt.get("data", {}) if vt.get("success") else {}

    malicious = int(vt_data.get("malicious", 0) or 0)
    suspicious = int(vt_data.get("suspicious", 0) or 0)
    harmless = int(vt_data.get("harmless", 0) or 0)

    if malicious == 0 and suspicious == 0:
        verdict = "SAFE"
        score = 10

    elif malicious == 1 and suspicious <= 1:
        verdict = "SUSPICIOUS"
        score = 50

    elif malicious <= 3:
        verdict = "SUSPICIOUS"
        score = 65

    else:
        verdict = "DANGEROUS"
        score = 90

    return {
        "verdict": verdict,
        "risk_score": score,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }


def call_groq(target, source_results, risk):

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not configured.")

    prompt = f"""
You are a cybersecurity analyst.

Analyze this target:

TARGET:
{target}

SECURITY DATA:
{json.dumps(source_results, indent=2, default=str)}

BASE RISK:
{json.dumps(risk, indent=2)}

Important:
- One isolated VirusTotal malicious detection does NOT automatically
  mean DANGEROUS.
- Consider possible false positives.
- Do not invent facts.
- Base your answer only on the supplied evidence.

Return a concise security assessment containing:
1. Verdict
2. Risk score
3. Key reasons
4. Recommendation
"""

    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        json={
            "model": "llama-3.1-8b-instant",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a defensive cybersecurity analyst."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1
        },
        timeout=60
    )

    response.raise_for_status()

    data = response.json()

    return data["choices"][0]["message"]["content"]


st.markdown("### 🔎 Scan an IP, Domain or URL")

target = st.text_input(
    "Enter target",
    placeholder="example.com or https://example.com or 8.8.8.8"
)

scan = st.button(
    "🛡️ Scan with Cyberlense",
    use_container_width=True
)

if scan:

    valid, message = validate_target(target)

    if not valid:
        st.error(message)
        st.stop()

    st.success(message)

    with st.spinner("Collecting VirusTotal and WHOIS intelligence..."):

        source_results = run_sources(target)

    st.markdown("## 🔎 Security Intelligence")

    vt = source_results.get("VirusTotal", {})
    whois_result = source_results.get("WHOIS", {})

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("### 🦠 VirusTotal")

        if vt.get("success"):

            data = vt.get("data", {})

            a, b = st.columns(2)
            c, d = st.columns(2)

            with a:
                st.metric("Malicious", data.get("malicious", 0))

            with b:
                st.metric("Suspicious", data.get("suspicious", 0))

            with c:
                st.metric("Harmless", data.get("harmless", 0))

            with d:
                st.metric("Undetected", data.get("undetected", 0))

        else:
            st.warning(
                "VirusTotal unavailable: "
                + str(vt.get("error"))
            )

    with col2:

        st.markdown("### 🌐 WHOIS")

        if whois_result.get("success"):

            data = whois_result.get("data", {})

            st.write(
                "**Domain:**",
                data.get("domain", "N/A")
            )

            st.write(
                "**Registrar:**",
                data.get("registrar", "N/A")
            )

            st.write(
                "**Created:**",
                data.get("creation_date", "N/A")
            )

            if data.get("domain_age_days") is not None:
                st.write(
                    "**Domain Age:**",
                    f"{data['domain_age_days']:,} days"
                )

        else:
            st.warning(
                "WHOIS unavailable: "
                + str(whois_result.get("error"))
            )

    risk = calculate_risk(source_results)

    st.markdown("---")
    st.markdown("## 🛡️ Cyberlense Verdict")

    if risk["verdict"] == "SAFE":

        st.success(
            f"🟢 SAFE — Risk Score: {risk['risk_score']}/100"
        )

    elif risk["verdict"] == "SUSPICIOUS":

        st.warning(
            f"🟡 SUSPICIOUS — Risk Score: {risk['risk_score']}/100"
        )

    else:

        st.error(
            f"🔴 DANGEROUS — Risk Score: {risk['risk_score']}/100"
        )

    st.markdown("### 🤖 AI Security Assessment")

    try:

        with st.spinner("Groq AI is analyzing the evidence..."):

            assessment = call_groq(
                target,
                source_results,
                risk
            )

        st.write(assessment)

    except Exception as e:

        st.warning(
            "AI analysis unavailable: "
            + str(e)
        )

    with st.expander("🔍 View Technical Source Data"):
        st.json(source_results)

st.markdown("---")

st.caption(
    "Cyberlense uses VirusTotal, WHOIS and Groq AI. "
    "Results are informational and should not be treated "
    "as absolute proof of safety or maliciousness."
)
