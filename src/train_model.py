from __future__ import annotations
import json
from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from joblib import dump
from src.preprocessing import clean_dataset, feature_frame

ROOT=Path(__file__).resolve().parents[1]

def train(data_path=ROOT/'data'/'urls.csv'):
    data=clean_dataset(str(data_path)); X=feature_frame(data.url); y=data.label.astype(int)
    if y.nunique()!=2 or y.value_counts().min()<2: raise ValueError('Training data must contain at least two examples from each class.')
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    candidates={
        'Logistic Regression':make_pipeline(StandardScaler(),LogisticRegression(max_iter=1500,class_weight='balanced',random_state=42)),
        'Random Forest':RandomForestClassifier(n_estimators=300,min_samples_leaf=2,class_weight='balanced',random_state=42,n_jobs=-1),
    }
    reports={}; fitted={}
    for name,model in candidates.items():
        model.fit(X_train,y_train); scores=model.predict_proba(X_test)[:,1]; pred=(scores>=.5).astype(int)
        reports[name]={'accuracy':accuracy_score(y_test,pred),'precision':precision_score(y_test,pred,zero_division=0),'recall':recall_score(y_test,pred,zero_division=0),'f1':f1_score(y_test,pred,zero_division=0),'roc_auc':roc_auc_score(y_test,scores),'confusion_matrix':confusion_matrix(y_test,pred).tolist()}
        fitted[name]=model
    winner=max(reports,key=lambda n:(reports[n]['f1'],reports[n]['roc_auc']))
    fitted[winner].fit(X,y)
    (ROOT/'models').mkdir(exist_ok=True); dump(fitted[winner],ROOT/'models'/'phishing_model.joblib')
    metadata={'selected_model':winner,'metrics':reports,'feature_names':list(X.columns),'dataset_rows':len(data),'note':'Metrics are from a random split of the bundled illustrative dataset; they are not a real-world benchmark.'}
    (ROOT/'models'/'metrics.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    print(json.dumps(metadata,indent=2)); return metadata

if __name__=='__main__': train()
