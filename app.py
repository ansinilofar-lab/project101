from __future__ import annotations
import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from joblib import load
from src.feature_extraction import extract_features, normalize_url
from src.preprocessing import feature_frame

ROOT=Path(__file__).resolve().parent
MODEL_PATH=ROOT/'models'/'phishing_model.joblib'
app=Flask(__name__,template_folder='frontend',static_folder='frontend',static_url_path='/static')
_model=None

def get_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            from src.train_model import train
            train()
        _model=load(MODEL_PATH)
    return _model

@app.get('/')
def home(): return render_template('index.html')

@app.get('/health')
def health(): return jsonify({'status':'ok','model_loaded':_model is not None})

@app.post('/predict')
def predict():
    payload=request.get_json(silent=True) or {}
    raw=payload.get('url','')
    if not isinstance(raw,str): return jsonify({'error':'URL must be provided as text.'}),400
    try:
        normalized=normalize_url(raw)
        features=extract_features(normalized)
        score=float(get_model().predict_proba(feature_frame([normalized]))[0][1])
    except ValueError as exc: return jsonify({'error':str(exc)}),400
    except Exception: app.logger.exception('Prediction failed'); return jsonify({'error':'The scan could not be completed. Please try again.'}),500
    suspicious=[]
    if features['has_https']==0: suspicious.append('Does not use HTTPS')
    if features['is_ip_address']: suspicious.append('Uses an IP address instead of a domain name')
    if features['suspicious_keyword_count']: suspicious.append('Contains security or account related words')
    if features['has_at_symbol']: suspicious.append('Contains an @ symbol')
    if features['is_shortened']: suspicious.append('Uses a URL shortening service')
    if features['subdomain_count']>=3: suspicious.append('Contains many subdomains')
    phishing=score>=.5
    risk='High' if score>=.75 else ('Medium' if score>=.4 else 'Low')
    return jsonify({'input_url':raw.strip(),'normalized_url':normalized,'prediction':'Phishing' if phishing else 'Safe','phishing_probability':round(score,4),'risk_category':risk,'explanations':suspicious,'features':features,'disclaimer':'This is an estimate from a small educational demo dataset. It is not a security guarantee.'})

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=False)
