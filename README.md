Choudhury2004/Phishing-Website-Detection
A production‑ready project to detect phishing websites using machine learning and URL/HTML features. Includes data processing, model training, evaluation, API/CLI for inference, optional Chrome extension, and Docker deployment.
Key Features:
1. Multi‑model support: Logistic Regression, Random Forest, XGBoost/LightGBM, and optionally Deep Learning.
2. Rich feature set: URL lexical features, host/network features, HTML/JS features, and WHOIS/SSL metadata (when enabled).
3. Fast inference: Works with just the URL (no page fetch required) for low‑latency use cases.
4. Fast inference: Works with just the URL (no page fetch required) for low‑latency use cases.

phishing-detection/
├─ data/
│ ├─ raw/ # original datasets
│ ├─ interim/ # intermediate processed data
│ └─ processed/ # train/val/test splits
├─ models/
│ ├─ artifacts/ # saved models, encoders, scalers
│ └─ reports/ # metrics, confusion matrices
├─ src/
│ ├─ features.py # feature extraction (URL, HTML, DNS, SSL, WHOIS)
│ ├─ preprocess.py # cleaning, splitting, encoding, scaling
│ ├─ train.py # training loop
│ ├─ evaluate.py # metrics & plots
│ ├─ infer.py # batch/CLI inference
│ ├─ api.py # FastAPI app
│ └─ utils.py # helpers & config
├─ extension/ # Optional Chrome/Edge extension
├─ tests/ # unit tests
├─ notebooks/ # EDA & experiments
├─ requirements.txt # Python deps
├─ Makefile # common commands
├─ config.yaml # feature/model toggles
├─ Dockerfile # containerization
└─ README.md # this file
