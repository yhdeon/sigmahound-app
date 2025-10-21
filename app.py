from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import json
import re
from datetime import timedelta
import httpx
from perplexity import Perplexity
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'dsl;kfjsdlkjfl;sdjfl;sdjlf;jsd;fjsdfasdfdsfcvx'

# Session timeout configuration (30 minutes of inactivity)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize Perplexity client with extended timeout (5 minutes)
client = Perplexity(
    timeout=httpx.Timeout(
        connect=5.0,
        read=300.0,   # 5 minutes
        write=10.0,
        pool=10.0
    )
)

bcrypt = Bcrypt(app)

# Configuration
MODEL_NAME = "sonar"
KB_PATH = os.path.join("kb", "1.json")
THREAT_HUNTING_PATH = os.path.join("kb", "2.json")
SYSPROMPT_PATH = os.path.join("kb", "sysprompt.json")

# Pre-hashed credentials
HASHED_PASSWORD = bcrypt.generate_password_hash("SAismyfavouritecourse!").decode('utf-8')
VALID_USERNAME = "TonyFromLCsigns"


@app.before_request
def make_session_permanent():
    """Enable session timeout - refreshes on each request"""
    session.permanent = True


def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def load_json(path):
    """Utility to safely load a JSON file."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return {}


def is_topic_allowed_llm(message):
    """
    Use LLM to check if query is IT/security related.
    Returns (is_allowed, reason)
    """
    message_lower = message.lower().strip()
    
    # Always allow meta-questions about the bot itself (skip LLM check)
    meta_questions = [
        'who are you', 'what are you', 'what can you do', 'what do you do',
        'tell me about yourself', 'introduce yourself', 'your purpose',
        'what is your name', 'what\'s your name', 'help', 'hello', 'hi', 'hey'
    ]
    
    for meta in meta_questions:
        if meta in message_lower:
            return True, None  # Skip guardrail for meta questions
    
    try:
        guard_prompt = f"""You are a topic classifier. Determine if this user query is related to:
            - Cybersecurity, threat hunting, malware, APT groups
            - IT infrastructure, networking, systems administration
            - Security operations, incident response
            - Computer security, hacking, vulnerabilities

            Query: "{message}"

            Respond with ONLY:
            - "ALLOWED" if the query is IT/security related
            - "BLOCKED: [reason]" if it's not related to IT/security

            # Your response:"""

        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a strict topic classifier for an IT security chatbot."},
                {"role": "user", "content": guard_prompt}
            ]
        )
        
        response = completion.choices[0].message.content.strip().upper()
        
        if response.startswith("ALLOWED"):
            return True, None
        else:
            # Extract reason if provided
            reason = response.replace("BLOCKED:", "").strip()
            if not reason:
                reason = "I'm Sigmahound, a security-focused assistant. I can only answer questions related to cybersecurity, threat hunting, APT analysis, and IT security topics. Please ask questions related to these areas."
            return False, reason
            
    except Exception as e:
        # If guardrail fails, allow the query (fail-open)
        print(f"Guardrail error: {e}")
        return True, None

def build_context(include_threat_hunting=False):
    """
    Combine system prompt and KB into one context string.
    Always includes APT41 KB to maintain Sigmahound identity.
    """
    sys_data = load_json(SYSPROMPT_PATH)
    context_name = sys_data.get("context_name", "Unnamed Context")
    system_prompt = sys_data.get("system_prompt", "(No system prompt provided.)")
    
    # ALWAYS include APT41 KB - this grounds the model and maintains identity
    kb_data = load_json(KB_PATH)
    kb_text = json.dumps(kb_data, indent=2, ensure_ascii=False)
    
    combined_context = (
        f"Context: {context_name}\n"
        f"System instruction:\n{system_prompt}\n\n"
        f"Here is the relevant knowledge base:\n{kb_text}"
    )
    
    # Add threat hunting rules ONLY when requested
    if include_threat_hunting:
        th_data = load_json(THREAT_HUNTING_PATH)
        th_text = json.dumps(th_data, indent=2, ensure_ascii=False)
        combined_context += (
            f"\n\n--- THREAT HUNTING RULES ---\n"
            f"{th_text}\n\n"
            f"IMPORTANT INSTRUCTION: When the user asks for threat hunting rules or Sigma rules for APT41, "
            f"you MUST return the EXACT rules provided above in the 'Rules' array. "
            f"Do NOT generate new rules. Do NOT modify the queries. "
            f"Present each rule with its Name, Description, Query, Tags, and Level exactly as provided. "
            f"Format them clearly for the user to copy and use directly."
        )
    
    return combined_context


def detect_threat_hunting_query(message):
    """
    Detect if the message is asking for threat hunting rules.
    Returns True if threat hunting related.
    """
    message_lower = message.lower()
    
    # Threat hunting keywords
    threat_hunting_keywords = [
        'threat hunting', 'hunting rule', 'detection rule',
        'sigma rule', 'hunting quer', 'detection quer',
        'generate rule', 'create rule', 'show rule'
    ]
    
    # Check if message contains threat hunting keywords
    for keyword in threat_hunting_keywords:
        if keyword in message_lower:
            return True
    
    return False


def detect_apt_query(message):
    """
    Detect if the message is asking about APT groups or campaigns.
    Returns (is_apt_query, apt_name) tuple.
    """
    message_lower = message.lower()
    
    # Pattern matching for standard APT queries
    apt_patterns = [
        r'\bapt\s*\d+',  # APT41, APT 41, etc.
        r'\bapt\s+\w+',  # APT Group, APT Actor, etc.
        r'apt\d+',       # apt41, apt28, etc.
    ]
    
    # Check for APT mentions
    for pattern in apt_patterns:
        match = re.search(pattern, message_lower)
        if match:
            apt_name = match.group(0).strip()
            return True, apt_name
    
    # APT41 aliases
    apt41_aliases = [
        'winnti', 'barium', 'wicked panda', 'brass typhoon', 'double dragon'
    ]
    
    # Check for aliases
    for alias in apt41_aliases:
        if alias in message_lower:
            return True, 'apt41'
    
    # Check for campaign-specific keywords
    campaign_keywords = [
        'dust campaign', 'dustpan', 'dusttrap',
        'threat actor', 'threat group', 'attack campaign'
    ]
    
    for keyword in campaign_keywords:
        if keyword in message_lower:
            return True, 'apt41'
    
    return False, None


def extract_visualization_data():
    """
    Extract relevant data from KB for visualization.
    Returns the KB data if it contains TTPs.
    """
    kb_data = load_json(KB_PATH)
    
    # Check if KB contains campaign data with TTPs
    for key, value in kb_data.items():
        if isinstance(value, dict) and 'TTPs' in value:
            return kb_data
    
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Verify credentials
        if username == VALID_USERNAME and bcrypt.check_password_hash(HASHED_PASSWORD, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template("login.html", error="Invalid username or password")
    
    # If already logged in, redirect to home
    if 'logged_in' in session:
        return redirect(url_for('home'))
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.get("/")
@login_required
def home():
    return render_template("index.html")


@app.post("/api/chat")
@login_required
def chat():
    user_message = request.json.get("message", "")

    if not user_message.strip():
        return jsonify({"reply": "Please enter a message."}), 400

    # GUARDRAIL: Check topic with LLM before processing
    is_allowed, rejection_reason = is_topic_allowed_llm(user_message)
    if not is_allowed:
        return jsonify({
            "reply": rejection_reason,
            "is_apt_query": False,
            "apt_name": None,
            "is_threat_hunting": False
        })

    # Detect query types
    is_threat_hunting = detect_threat_hunting_query(user_message)
    is_apt_query, apt_name = detect_apt_query(user_message)
    
    # Build context - always include base KB, add threat hunting if requested
    system_context = build_context(include_threat_hunting=(is_threat_hunting and is_apt_query))
    
    # Modify user message for threat hunting queries to be more explicit
    if is_threat_hunting and is_apt_query:
        user_message = (
            f"Please provide the EXACT threat hunting rules from the provided threat hunting rules JSON. "
            f"Return all rules with their Name, Description, Query, Tags, and Level fields. "
            f"Do not generate new rules - only return what is in the threat hunting rules data provided."
        )

    try:
        # Make API call using Perplexity client
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_context},
                {"role": "user", "content": user_message}
            ]
        )
        
        # Extract reply from completion
        reply = completion.choices[0].message.content
        
        # Prepare response
        response = {
            "reply": reply,
            "is_apt_query": is_apt_query,
            "apt_name": apt_name,
            "is_threat_hunting": is_threat_hunting
        }
        
        # If APT query detected (but not threat hunting), check if we have visualization data
        if is_apt_query and not is_threat_hunting:
            viz_data = extract_visualization_data()
            if viz_data:
                response["has_visualization"] = True
                response["visualization_data"] = viz_data
            else:
                response["has_visualization"] = False
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"reply": f"Error contacting Perplexity API: {str(e)}"}), 500


@app.get("/visualization")
@login_required
def visualization():
    return render_template("visualization.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8493, debug=True)
