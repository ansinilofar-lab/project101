# PhishGuard — Phishing URL Detector

A small, locally running educational phishing URL detector. It extracts 15 lexical and structural features, trains and compares Logistic Regression and Random Forest classifiers, and serves predictions through a Flask API and responsive dashboard.

> **Academic demo only.** `data/urls.csv` is a tiny illustrative dataset, not a representative public benchmark. Reported metrics are only a random holdout score on that dataset and must not be treated as real-world performance. A Safe result is not a guarantee. Do not use this demo to make security decisions.

## Features

- Modular feature extraction for URL length, punctuation, digits, HTTPS, IP hosts, subdomains, suspicious keywords, domain/path length, query parameters, `@`, entropy, and known shorteners.
- Dataset cleanup, duplicate removal, invalid URL filtering, and stratified train/test split. The fitted scaler is inside the Logistic Regression pipeline to avoid test leakage.
- Model comparison with accuracy, precision, recall, F1, ROC-AUC, and confusion matrices. The best F1 model is retrained on all bundled data and saved with Joblib.
- Flask endpoints: `GET /`, `POST /predict`, and `GET /health`.
- Browser scan history stored only in local browser storage.
- Submitted URLs are never visited. HTTPS is only one input feature.

## Requirements

Python 3.10 or newer. Install packages in a virtual environment:

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Train and run

```bash
python -m src.train_model
python app.py
```

Open `http://127.0.0.1:5000`. Training prints the model comparison and writes `models/metrics.json` plus `models/phishing_model.joblib`. The model file is ignored by Git and can always be regenerated from the committed CSV. The app also trains automatically on first run if the model file is missing.

## API example

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/login"}'
```

Response includes the normalized URL, Safe/Phishing prediction, phishing probability, risk category, extracted features, and basic lexical explanations. The probability is a model score, not a calibrated real-world likelihood.

Health check:

```bash
curl http://127.0.0.1:5000/health
```

## Project layout

```text
app.py                  Flask app and API
src/feature_extraction.py  URL normalization and 15 features
src/preprocessing.py    Dataset cleanup and feature matrix
src/train_model.py      Train, compare, evaluate, save
frontend/               Dashboard HTML, CSS, and JavaScript
data/urls.csv           Small illustrative labeled dataset
models/                 Generated model and metrics
notebooks/              Reserved for experiments
```

## Use a real dataset for research

For academic evaluation, replace `data/urls.csv` with a permitted public dataset having `url,label` columns (`safe`/`legitimate` and `phishing`/`malicious` labels). Deduplicate before splitting and consider a time-based or domain-grouped holdout so closely related URLs do not appear in both train and test. Re-run training and document dataset origin, license, collection date, class balance, and evaluation protocol. Avoid downloading or opening submitted URLs.

## Limitations

Lexical patterns can miss new attacks and can flag benign URLs. Attackers can manipulate URL spelling. The bundled sample is intentionally small and not suitable for deployment. No external reputation service, DNS lookup, or target page fetch is performed.
