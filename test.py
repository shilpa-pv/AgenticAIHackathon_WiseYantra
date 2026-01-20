import warnings
warnings.filterwarnings('ignore')

import joblib
import json
import pandas as pd
import numpy as np
import httpx
from langchain_openai import ChatOpenAI

access_token='eyJhbGciOiJSUzI1NiIsImtpZCI6ImF0LTE2MDk1NTkzNDAiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3Njg2NjI5NzQsImp0aSI6Ijc3N2NkZjMwLWM4ZGQtNDdjMS1iODYyLTMwMThhMmJjNGYxZCIsInN1YiI6IlNoaWxwYS5QdkBkZWxsLmNvbSIsImNsaWVudF9pZCI6ImExNGI0MDg2LWQ2ODItNGI4MS1hMDdjLTU3ZGE1MTQzN2VmZSIsInByb2ZpbGVpZCI6IjZkZTc3M2JkLTViMDMtNDEzZi04NGE2LTk5NmMwYjE4ZGJmMyIsIkFEQkRHIjoiODI4MjUwIiwiYXV0aHNyYyI6IkFEIiwiQURVTiI6IlNoaWxwYV9QdiIsIkFERE9NIjoiQU1FUklDQVMiLCJQWVNJRCI6ImU1Njg3N2FkLWRmZTItNDM0My1hMzNlLTQ1OGM5NGY2ZDk0MSIsIkVYVElEUCI6IlRydWUiLCJzdWJ0eXBlIjoidXNlciIsInR0eSI6ImF0Iiwic2NvcGUiOlsiYWlhLWdhdGV3YXkuYWlkYWFzLmRldiIsImFpYS1nYXRld2F5LmZpbmV0dW5pbmciLCJhaWEtZ2F0ZXdheS5nZW5haS5kZXYiLCJhaWEtZ2F0ZXdheS5nZW5haS5kZXYuYmF0Y2giLCJhaWEtZ2F0ZXdheS5ncm91bmQtdHJ1dGgiLCJhaWEtZ2F0ZXdheS5sbG1qIiwiYWlhLWdhdGV3YXkucHJvbXB0LWV2YWwiLCJhaWEtZ2F0ZXdheS5wcm9tcHQtZ2VuIl0sImF1ZCI6ImFpYS1nYXRld2F5IiwibmJmIjoxNzY4NjYyOTc0LCJleHAiOjE3Njg2NjQ3NzQsImlzcyI6Imh0dHA6Ly93d3cuZGVsbC5jb20vaWRlbnRpdHkifQ.WTqK4D-g6ik8pA_PH2RRg2WnuPKrLulVUb1mIEkf8og9fPHZpjyRrgEPyjd5R5x--xBBzgQyW_bnJYvABAAYzq5lLvwhclTnkqh_uymDMxYrGBuMu0ha3hV8W-PsWsaxw9m7sYYciKiYCTJQF5lI8bcGq6iPGxDAyFNfZxFKNDDgMOujoYf0QQGK_DWPkMm0cfsQekF8Hq1CC1A4hJdNm_gn6RSjSBhjiefCc7BS4Av9NK4rTKGJF8o718x9Hcr3Uq3rlxxAm6wKXY-x_oohqzvoTBT_lZASUqS5rh3D-APJ4tZMdvOSucOut5XrFfjuXRDh-h8O78hsbY-6UvoewA'
# LLM Setup
# access_token = 'YOUR_ACCESS_TOKEN'  # Replace with your token
http_async_client = httpx.AsyncClient(verify=False)
llm = ChatOpenAI(
    model="gemma-3-27b-it",
    base_url="https://genai-api-dev.dell.com/v1",
    api_key=access_token,
    http_async_client=http_async_client
)

# Load model and preprocessing artifacts
model = joblib.load("model.pkl")
label_encoders = joblib.load("label_encoders.pkl")
scaler = joblib.load("scaler.pkl")

with open("feature_schema.json", "r") as f:
    FEATURE_ORDER = json.load(f)

with open("categorical_cols.json", "r") as f:
    categorical_cols = json.load(f)

# Add perm if not in categorical_cols (it's also a string column)
if 'perm' not in categorical_cols:
    categorical_cols.append('perm')

def predict(feature_json):
    # Create DataFrame
    df = pd.DataFrame([feature_json])
    
    # Drop columns not used in training
    cols_to_drop = ['ts', 'minute', 'new_path', 'path', 'filename', 'cmdline', 'label']
    df = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')
    
    # Replace empty strings with NaN
    df = df.replace('', np.nan)
    
    # Encode ALL string/categorical columns
    for col in df.columns:
        if df[col].dtype == 'object' or col in categorical_cols:
            df[col] = df[col].fillna('unknown').astype(str)
            if col in label_encoders:
                le = label_encoders[col]
                df[col] = df[col].apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else 0
                )
            else:
                # Column not in encoders, set to 0
                df[col] = 0
    
    # Fill numeric NaN with 0
    df = df.fillna(0)
    
    # Ensure columns match training data
    for col in FEATURE_ORDER:
        if col not in df.columns:
            df[col] = 0
    df = df[FEATURE_ORDER]
    
    # Scale features
    df_scaled = scaler.transform(df)
    
    # Predict
    prediction = model.predict(df_scaled)[0]
    prob = model.predict_proba(df_scaled)[0]
    
    return {
        "prediction": "COMPROMISED" if prediction == 1 else "SAFE",
        "is_attack": bool(prediction == 1),
        "confidence": float(round(max(prob) * 100, 2))
    }

def get_llm_analysis(sample_dict, ml_result):
    """Get LLM-based analysis for reasons and remediation"""
    prompt = f"""You are a cybersecurity analyst. Analyze this system event and respond ONLY with valid JSON.

## INPUT DATA:
- Host: {sample_dict.get('host', 'N/A')}
- Process ID: {sample_dict.get('pid', 'N/A')}
- Parent PID: {sample_dict.get('ppid', 'N/A')}
- User: {sample_dict.get('user', 'N/A')}
- Executable: {sample_dict.get('exe', 'N/A')}
- System Call: {sample_dict.get('syscall', 'N/A')}
- Directory: {sample_dict.get('dir', 'N/A')}
- File Extension: {sample_dict.get('ext', 'N/A')}
- Bytes Written: {sample_dict.get('bytes_written', 'N/A')}
- Is Sensitive Path: {sample_dict.get('is_sensitive_path', 'N/A')}
- Is Backup Path: {sample_dict.get('is_backup_path', 'N/A')}

## ML PREDICTION: {ml_result['prediction']} (Confidence: {ml_result['confidence']}%)

Based ONLY on the input data above, respond with this exact JSON structure:
{{
    "suspicious_data_fields": ["<field_name_1>", "<field_name_2>"],
    "reasons": [
        "<reason_1_based_on_data>",
        "<reason_2_based_on_data>"
    ],
    "remediation": [
        "<action_1_with_specific_host_pid_dir>",
        "<action_2_with_specific_host_pid_dir>",
        "<action_3_with_specific_host_pid_dir>"
    ]
}}

Return ONLY the JSON, no other text."""

    messages = [{"role": "user", "content": prompt}]
    
    try:
        response = llm.invoke(messages)
        response_text = response.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        return json.loads(response_text)
    except Exception as e:
        # Fallback response
        return get_fallback_analysis(sample_dict, ml_result)

def get_fallback_analysis(sample_dict, ml_result):
    """Fallback analysis if LLM fails"""
    suspicious_fields = []
    if sample_dict.get('syscall') in ['unlink', 'rename']:
        suspicious_fields.append("syscall")
    if sample_dict.get('is_sensitive_path'):
        suspicious_fields.append("is_sensitive_path")
    if 'python' in str(sample_dict.get('exe', '')):
        suspicious_fields.append("exe")
    
    return {
        "suspicious_data_fields": suspicious_fields if suspicious_fields else ["None detected"],
        "reasons": [
            f"System call '{sample_dict.get('syscall')}' detected on path '{sample_dict.get('dir')}'",
            f"Process '{sample_dict.get('exe')}' executed by user '{sample_dict.get('user')}'"
        ],
        "remediation": [
            f"Monitor host '{sample_dict.get('host')}' for further activity",
            f"Investigate process PID {sample_dict.get('pid')} and parent PID {sample_dict.get('ppid')}",
            f"Review directory '{sample_dict.get('dir')}' for unauthorized changes"
        ]
    }

def analyze(sample_dict):
    """Combined ML prediction + LLM analysis"""
    # Get ML prediction
    ml_result = predict(sample_dict)
    
    # Get LLM analysis
    llm_result = get_llm_analysis(sample_dict, ml_result)
    
    # Combine results
    return {
        "prediction": ml_result["prediction"],
        "confidence": ml_result["confidence"],
        **llm_result
    }

# 5 Samples: 4 BENIGN (negative), 1 RANSOMWARE (positive)

# Sample 1: BENIGN - Normal text file edit
sample_benign_1 = {
    "host": "vm-01", "pid": 2345, "ppid": 1200, "uid": 1001,
    "user": "alice", "exe": "/usr/bin/vim", "syscall": "write",
    "dir": "/home/alice/docs", "ext": "txt", "bytes_written": 2048,
    "perm": "rw-r--r--", "owner": "alice", "retval": 0,
    "is_sensitive_path": False, "is_backup_path": False
}

# Sample 2: BENIGN - Log file rotation
sample_benign_2 = {
    "host": "web-server", "pid": 5678, "ppid": 1, "uid": 0,
    "user": "root", "exe": "/usr/sbin/logrotate", "syscall": "write",
    "dir": "/var/log", "ext": "log", "bytes_written": 1024,
    "perm": "rw-r-----", "owner": "root", "retval": 0,
    "is_sensitive_path": False, "is_backup_path": False
}

# Sample 3: BENIGN - Normal backup operation
sample_benign_3 = {
    "host": "backup-srv", "pid": 9012, "ppid": 100, "uid": 500,
    "user": "backup", "exe": "/usr/bin/rsync", "syscall": "write",
    "dir": "/backup/daily", "ext": "tar", "bytes_written": 524288,
    "perm": "rw-------", "owner": "backup", "retval": 0,
    "is_sensitive_path": False, "is_backup_path": True
}

# Sample 4: BENIGN - Database query
sample_benign_4 = {
    "host": "db-server", "pid": 3456, "ppid": 200, "uid": 999,
    "user": "mysql", "exe": "/usr/sbin/mysqld", "syscall": "read",
    "dir": "/var/lib/mysql", "ext": "ibd", "bytes_written": 0,
    "perm": "rw-rw----", "owner": "mysql", "retval": 0,
    "is_sensitive_path": False, "is_backup_path": False
}

# Sample 5: RANSOMWARE - Suspicious file deletion on sensitive path
sample_ransomware = {
    "host": "app1", "pid": 37029, "ppid": 87, "uid": 806,
    "user": "backup", "exe": "/usr/bin/python3", "syscall": "unlink",
    "dir": "/opt/app/data", "ext": "xls", "bytes_written": 0,
    "perm": "", "owner": "", "retval": 0,
    "is_sensitive_path": True, "is_backup_path": False
}

# Test all samples
samples = [
    ("BENIGN_1 (vim edit)", sample_benign_1),
    ("BENIGN_2 (logrotate)", sample_benign_2),
    ("BENIGN_3 (rsync backup)", sample_benign_3),
    ("BENIGN_4 (mysql read)", sample_benign_4),
    ("RANSOMWARE (python unlink)", sample_ransomware)
]

if __name__ == "__main__":
    result = analyze(sample_ransomware)
    print(type(result))
    print(json.dumps(result, indent=2))

    # print("=" * 60)
    # for name, sample in samples:
    #     print(f"\n{name}:")
    #     result = analyze(sample)  # Combined ML + LLM
    #     print(json.dumps(result, indent=2))
    # print("\n" + "=" * 60)