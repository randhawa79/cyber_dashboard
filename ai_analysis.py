import google.generativeai as genai
from config import get_gemini_api_key, logger

def generate_ai_executive_summary(vulnerabilities_df, news_df, alerts_df):
    """
    Leverages Gemini LLM to create an executive briefing from structured dashboard metrics.
    Gracefully reverts to an embedded algorithmic rule-engine summary if keys are missing.
    """
    api_key = get_gemini_api_key()
    
    # Context Assembly
    vuln_count = len(vulnerabilities_df)
    news_count = len(news_df)
    alert_count = len(alerts_df)
    
    critical_vulns = vulnerabilities_df[vulnerabilities_df['cvss_score'] >= 8.5]['cve_id'].tolist()
    rbi_alerts = alerts_df[alerts_df['source'] == 'RBI']['title'].tolist()

    if api_key:
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a senior enterprise cybersecurity expert and virtual CISO advising the Board of a highly regulated Payment Gateway company.
            Review the past 24 hours of telemetry context:
            - Actively Exploited Critical Vulnerabilities: {vuln_count} total. IDs: {critical_vulns}
            - Global Cybersecurity News Events: {news_count} entries recorded.
            - Local Compliance Regulator Notices (RBI/CERT-In/NPCI): {alert_count} items. Active Directives: {rbi_alerts}
            
            Provide a strictly professional, actionable briefing containing:
            1. An executive narrative of the operational threat horizon.
            2. High-impact operational vectors requiring engineering mitigations today.
            Do not use generic filler language. Speak directly to standard regulatory enforcement risks.
            """
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini API execution failure. Falling back to internal engine. Error: {str(e)}")
            
    # Algorithmic Heuristic Fallback Engine
    fallback_summary = f"""
    ### 🛡️ Core Infrastructure Security Assessment (Heuristic Engine)
    
    **Operational Status Profile**: High Alert Environment. 
    A total of **{vuln_count} actively exploited systems** are under tracking constraints, with vulnerabilities {critical_vulns} present in the wild.
    
    **Regulated Mandate Impact Vectors**:
    * **RBI/NPCI Adjustments**: {len(rbi_alerts)} pending structural adjustments detected. Intercept workflows require engineering updates to comply with payment-agnostic velocity mandates.
    * **Action Matrix**: Review authentication endpoints within 24 hours. Verify logging pipeline consistency across all production networks.
    """
    return fallback_summary