from __future__ import annotations
import pandas as pd
from src.feature_extraction import extract_features

def clean_dataset(path: str) -> pd.DataFrame:
    df=pd.read_csv(path)
    if not {'url','label'}.issubset(df.columns): raise ValueError("Dataset must have 'url' and 'label' columns.")
    df=df[['url','label']].dropna().drop_duplicates(subset='url')
    df['label']=df['label'].map({'safe':0,'legitimate':0,'phishing':1,'malicious':1,0:0,1:1})
    df=df.dropna(subset=['label'])
    valid=[]
    for url in df['url'].astype(str):
        try: extract_features(url); valid.append(True)
        except ValueError: valid.append(False)
    return df.loc[valid].reset_index(drop=True)

def feature_frame(urls): return pd.DataFrame([extract_features(str(url)) for url in urls])
