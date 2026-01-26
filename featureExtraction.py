import re
import os
import joblib
import numpy as np
import socket
from urllib.parse import urlparse
from sklearn.ensemble import GradientBoostingClassifier

# ==============================================================================
# MODEL INITIALIZATION
# ==============================================================================
MODEL_DIR = 'models'
MODEL_PATH = os.path.join(MODEL_DIR, 'Phishing.pkl')

def _generate_clean_model():
    """Generates a Gradient Boosting model trained on synthetic rules."""
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
    
    # We create a synthetic training set so the model understands specific "red flags"
    # Features: [IP, @, Len, Dep, //, HTTPS, Short, Pre/Suf, DNS, Age, Exp, iframe, Mouse, Click, Redir, Ext, Digit, Case]
    X_train = [
        [0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0], # Perfectly clean (HTTPS exists, DNS exists)
        [1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0], # Has IP -> Phishing
        [0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0], # Has @ -> Phishing
        [0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0], # No HTTPS AND Missing DNS -> Phishing
        [0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0], # Has HTTPS but Missing DNS -> Phishing
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0], # Unusual Extension -> Phishing
        [0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0], # Shortened URL -> Phishing
        [0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0], # Dash in domain -> Phishing
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1], # Digits + Mixed Case -> Suspicious/Phishing
    ]
    # Labels: 0 = Legitimate, 1 = Phishing
    y_train = [0, 1, 1, 1, 1, 1, 1, 1, 1]

    # Convert to numpy arrays
    X_train = np.array(X_train)
    y_train = np.array(y_train)
    
    # Initialize Gradient Boosting with more sensitivity
    model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
    model.fit(X_train, y_train)
    joblib.dump(model, MODEL_PATH)

if not os.path.exists(MODEL_PATH):
    _generate_clean_model()

# ==============================================================================
# FEATURE EXTRACTION LOGIC
# ==============================================================================

def featureExtraction(url):
    features = [0] * 18
    url_lower = url.lower()
    
    # --- WEBSITE EXISTENCE CHECK (DNS CHECK) ---
    website_exists = True
    try:
        check_url = url_lower
        if not (check_url.startswith('http://') or check_url.startswith('https://')):
            check_url = 'http://' + check_url
        
        domain = urlparse(check_url).netloc
        if not domain:
            domain = url_lower.split('/')[0]

        socket.setdefaulttimeout(2) # Faster timeout
        socket.gethostbyname(domain)
    except Exception:
        website_exists = False

    # 0. Have IP
    features[0] = 1 if re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])', url) else 0
    # 1. Have @ symbol
    features[1] = 1 if "@" in url else 0
    # 2. URL Length (Short is fine, very long is suspicious)
    features[2] = 1 if len(url) > 75 else 0
    # 3. URL Depth
    features[3] = url.count('/')
    # 4. Redirection //
    features[4] = 1 if url.rfind('//') > 7 else 0
    # 5. HTTPS in URL (0 if secure, 1 if insecure/no https)
    features[5] = 1 if url_lower.startswith('https://') else 0
    # 6. URL Shortening
    features[6] = 1 if re.search(r"bit\.ly|goo\.gl|tinyurl", url) else 0
    # 7. Prefix/Suffix (Dash in domain)
    try:
        check_url = url if '://' in url else 'http://' + url
        features[7] = 1 if '-' in urlparse(check_url).netloc else 0
    except:
        features[7] = 0
    # 8. DNS Record (1 = Phishing/Does not exist)
    features[8] = 0 if website_exists else 1
    # 15. Unusual Extension
    features[15] = 1 if any(url_lower.endswith(ext) for ext in [".xyz", ".top", ".work", ".ml", ".ga", ".cf"]) else 0
    # 16. Numeric Digits
    features[16] = 1 if any(char.isdigit() for char in url) else 0
    # 17. Mixed Case Characters
    features[17] = 1 if any(c.islower() for c in url) and any(c.isupper() for c in url) else 0
    
    return features
