import requests
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class OllamaService:
    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "mistral"):
        self.base_url = base_url
        self.model = model
        self.timeout = 30

    def health_check(self) -> Dict[str, Any]:
        """Verify Ollama is reachable and model is available."""
        try:
            # Check if server is up
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return {"status": "error", "message": f"Ollama returned {resp.status_code}"}
            
            models = resp.json().get("models", [])
            model_names = [m["name"] for m in models]
            
            if self.model not in model_names and f"{self.model}:latest" not in model_names:
                return {
                    "status": "warning", 
                    "message": f"Model '{self.model}' not found in {model_names}",
                    "available_models": model_names
                }
            
            return {"status": "healthy", "model": self.model}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def generate(self, prompt: str, system_prompt: str = "") -> Optional[str]:
        """Generate text using local Ollama instance."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                }
            }
            resp = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json().get("response")
            else:
                logger.error(f"Ollama error {resp.status_code}: {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return None

    def summarize_finding(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Converts raw finding into AI-analyzed insights."""
        # Check health first
        health = self.health_check()
        if health["status"] == "error":
            return self._fallback_summary(vuln_data)

        prompt = f"""
        Analyze the following security finding:
        Title: {vuln_data.get('title')}
        Description: {vuln_data.get('description')}
        Severity: {vuln_data.get('severity')}
        CVE: {vuln_data.get('cve_id')}
        Evidence: {vuln_data.get('evidence')}
        URL: {vuln_data.get('url')}

        Return a JSON object with:
        - "summary": A concise technical summary (max 2 sentences).
        - "impact": The specific business risk.
        - "scenario": A likely exploit scenario.
        - "remediation": The #1 most effective first action.
        - "confidence": Float between 0.0 and 1.0.
        """
        
        system_prompt = "You are a professional security analyst. Return ONLY a valid JSON object."
        
        response_text = self.generate(prompt, system_prompt)
        if not response_text:
            return self._fallback_summary(vuln_data)

        try:
            # Attempt to parse JSON from response
            # Sometimes LLMs include markdown code blocks
            clean_json = response_text.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()
                
            return json.loads(clean_json)
        except Exception as e:
            logger.warning(f"Failed to parse Ollama JSON: {e}. Raw: {response_text}")
            return self._fallback_summary(vuln_data)

    def _fallback_summary(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic heuristic fallback if AI is unavailable."""
        severity = vuln.get("severity", "Low")
        return {
            "summary": f"Automated analysis for {vuln.get('title')}.",
            "impact": f"Potential {severity} risk to asset confidentiality or availability.",
            "scenario": "An attacker could leverage this weakness to gain unauthorized access or information disclosure.",
            "remediation": "Apply latest security patches and follow vendor hardening guidelines.",
            "confidence": 0.5
        }
