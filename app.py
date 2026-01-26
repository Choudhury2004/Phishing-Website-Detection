from flask import Flask, render_template, request
from featureExtraction import featureExtraction
import joblib
import os

app = Flask(__name__)

# Load the saved Gradient Boosting model
model_path = 'models/Phishing.pkl'
model = joblib.load(model_path) if os.path.exists(model_path) else None

feature_names = [
    "Have IP", "Have '@' symbol", "Long URL", "URL Depth", "Redirection",
    "HTTPS Protocol", "URL Shortening", "Dash in Domain", "Missing DNS Record",
    "Domain Age", "Domain Expiry", "Contains iframe", "Mouse Over",
    "Right Click Disabled", "Multiple Redirections", "Suspicious Extension",
    "Numeric Digits", "Mixed Case"
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        features = featureExtraction(url)

        # 1. Get prediction from Gradient Boosting Model
        # model.predict returns [0] or [1]
        prediction = model.predict([features])[0]

        # 2. "Non-Secure" & Legitimacy Logic:
        # If DNS record is missing (features[8]==1), it's definitely Phishing.
        # Otherwise, follow the ML model's decision.
        if features[8] == 1 or prediction == 1:
            prediction_text = "Phishing"
        else:
            prediction_text = "Legitimate"

        # List triggered features for the UI
        triggered_features = [feature_names[i] for i in range(len(features)) if features[i] == 1]
        
        # If it's not HTTPS, add it to the list of reasons why it's "non secure"
        if features[5] == 0: # In our featureExtraction, 0 meant no https
             if "HTTPS Protocol" not in triggered_features:
                 triggered_features.append("Insecure Connection (No HTTPS)")

        return render_template('result.html', 
                               url=url, 
                               prediction_text=prediction_text, 
                               features=triggered_features)

if __name__ == '__main__':
    app.run(debug=True)
