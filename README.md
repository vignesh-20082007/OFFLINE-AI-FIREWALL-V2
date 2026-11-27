#OFFLINE AI Firewall V2

Welcome to AI Firewall V2, an advanced security middleware designed specifically for Large Language Model applications. Developed under Tanglish Innovations, this enterprise-grade solution provides robust bidirectional protection against data exfiltration, malicious prompt injections, and unauthorized agent tool usage.
Key Features
 * Statutory Data Redaction: Automatically detects and masks sensitive Indian PII including Aadhaar numbers, PAN cards, UPI IDs, and Indian phone numbers with high precision.
 * Bidirectional Guardrails: Inspects both incoming prompts and outgoing LLM responses to prevent indirect prompt injection and jailbreak attempts.
 * Agent Tool Governance: Enforces strict access policies on external tools and APIs, preventing unauthorized SQL execution or SSRF.
 * Comprehensive Metrics: Exposes a dedicated metrics endpoint for real-time monitoring of risk scores, policy violations, and latency.
Quick Start and Installation
Currently optimized for Linux environments running Python 3.12, follow these steps to deploy the AI Firewall:
 * Clone the Repository:

   git clone <repository-url>
cd ai-firewall

 * Install Dependencies: Ensure pyaml is installed for policy parsing.

   pip install -r requirements.txt

 * Execution: Run the validation suite to verify environment readiness.

   python ai_firewall.py --validate

 * Integration: Import the AIFirewall class into your LLM request pipeline.
