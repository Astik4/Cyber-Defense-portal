import re
import os

try:
    from google import genai
    from google.genai import types
    has_genai = True
except ImportError:
    has_genai = False

def analyze_threat(threat_input):
    """
    Simulated AI Threat analysis using regex and heuristic matching.
    If GEMINI_API_KEY is found and the google-genai library installed,
    it maps the threat using actual generative AI.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    
    if api_key and has_genai:
        try:
            client = genai.Client(api_key=api_key)
            prompt = f"""
            You are a senior SOC level 3 analyst. Analyze the following suspicious indicator/log snippet and provide a threat analysis in valid JSON format.
            Input to analyze: "{threat_input}"
            
            Return ONLY a valid JSON object with these exact keys, nothing else:
            - "category": Threat category (e.g., "Malicious IP Connection").
            - "severity": "Low", "Medium", "High", or "Critical".
            - "confidence": confidence percentage.
            - "attack_type": the likely attack type.
            - "mitre_mapping": the relevant MITRE ATT&CK technique (e.g., "T1071").
            - "explanation": a detailed explanation of the risk.
            - "recommended_action": primary immediate action to take.
            """
            
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
            )
            
            import json
            text = response.text.strip('`').removeprefix('json').strip()
            ai_data = json.loads(text)
            
            ai_data["mitigation"] = ["Consult local network admin", "Check lateral movement", "Increase EDR sensor levels"]
            return ai_data
            
        except Exception as e:
            print(f"GenAI Analysis failed, falling back to heuristics: {e}")
    
    # --- Heuristic Fallback Strategy ---

    # 1. IP Check
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    if re.search(ip_pattern, threat_input):
        return {
            "category": "Malicious IP Connection",
            "severity": "High",
            "confidence": "85%",
            "attack_type": "Command & Control / Botnet",
            "mitre_mapping": "T1071.001 - Application Layer Protocol: Web Protocols",
            "explanation": f"The provided IP ({re.findall(ip_pattern, threat_input)[0]}) matches known patterns of a malicious C2 server attempting to communicate with an internal host.",
            "recommended_action": "Block IP instantly at the firewall level.",
            "mitigation": ["Add IP to firewall blacklist", "Isolate affected host", "Run full EDR scan"]
        }
        
    # 2. Process / Path Check
    elif "exe" in threat_input.lower() or "cmd" in threat_input.lower() or "powershell" in threat_input.lower():
         return {
            "category": "Suspicious Process Execution",
            "severity": "Critical",
            "confidence": "92%",
            "attack_type": "Ransomware Execution / Obfuscation",
            "mitre_mapping": "T1059 - Command and Scripting Interpreter",
            "explanation": "A local process is attempting actions characteristic of ransomware (e.g., rapid file encryption from a Temp directory) or unauthorized scripting.",
            "recommended_action": "Kill process immediately.",
            "mitigation": ["Terminate process ID", "Quarantine the executable file", "Restore from last known good backup"]
        }

    # 3. Default Analysis
    return {
        "category": "Anomalous Behavior",
        "severity": "Medium",
        "confidence": "60%",
        "attack_type": "Unknown Anomaly / Port Scan",
        "mitre_mapping": "T1046 - Network Service Discovery",
        "explanation": "Input did not match highly critical signatures, but exhibits traits of network discovery or enumeration.",
        "recommended_action": "Monitor traffic closely.",
        "mitigation": ["Increase logging verbosity", "Review recent SIEM alerts", "Check firewall rules"]
    }
