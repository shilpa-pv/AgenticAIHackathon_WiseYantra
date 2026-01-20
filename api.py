from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import prediction functions from test.py
from test import predict, get_llm_analysis, get_fallback_analysis, analyze

app = FastAPI(title="Ransomware Detection API")

# CORS for Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sample assets with their data (simulating monitored assets)
ASSET_DATA = {
    "a1": {
        "host": "app1", "pid": 37029, "ppid": 87, "uid": 806,
        "user": "backup", "exe": "/usr/bin/python3", "syscall": "unlink",
        "dir": "/opt/app/data", "ext": "xls", "bytes_written": 0,
        "perm": "", "owner": "", "retval": 0,
        "is_sensitive_path": True, "is_backup_path": False
    },
    "a2": {
        "host": "vm-01", "pid": 2345, "ppid": 1200, "uid": 1001,
        "user": "alice", "exe": "/usr/bin/vim", "syscall": "write",
        "dir": "/home/alice/docs", "ext": "txt", "bytes_written": 2048,
        "perm": "rw-r--r--", "owner": "alice", "retval": 0,
        "is_sensitive_path": False, "is_backup_path": False
    },
    "a3": {
        "host": "web-server", "pid": 5678, "ppid": 1, "uid": 0,
        "user": "root", "exe": "/usr/sbin/logrotate", "syscall": "write",
        "dir": "/var/log", "ext": "log", "bytes_written": 1024,
        "perm": "rw-r-----", "owner": "root", "retval": 0,
        "is_sensitive_path": False, "is_backup_path": False
    },
    "a4": {
        "host": "backup-srv", "pid": 9012, "ppid": 100, "uid": 500,
        "user": "backup", "exe": "/usr/bin/rsync", "syscall": "write",
        "dir": "/backup/daily", "ext": "tar", "bytes_written": 524288,
        "perm": "rw-------", "owner": "backup", "retval": 0,
        "is_sensitive_path": False, "is_backup_path": True
    },
    "a5": {
        "host": "db-server", "pid": 3456, "ppid": 200, "uid": 999,
        "user": "mysql", "exe": "/usr/sbin/mysqld", "syscall": "read",
        "dir": "/var/lib/mysql", "ext": "ibd", "bytes_written": 0,
        "perm": "rw-rw----", "owner": "mysql", "retval": 0,
        "is_sensitive_path": False, "is_backup_path": False
    },
    # RANSOMWARE - Suspicious deletion of backup files
    "a6": {
        "host": "file-server", "pid": 48291, "ppid": 1, "uid": 0,
        "user": "www-data", "exe": "/usr/bin/python3", "syscall": "unlink",
        "dir": "/var/www/uploads", "ext": "doc", "bytes_written": 0,
        "perm": "", "owner": "", "retval": 0,
        "is_sensitive_path": True, "is_backup_path": False
    },
}

@app.get("/")
def root():
    return {"status": "Ransomware Detection API running"}

@app.get("/assets")
def get_all_assets():
    """Return all assets with their basic info"""
    assets = {}
    for asset_id in ASSET_DATA:
        assets[asset_id] = {"id": asset_id, "host": ASSET_DATA[asset_id]["host"]}
    return {"assets": assets}

@app.get("/asset/{asset_id}")
def get_asset_risk(asset_id: str):
    """Analyze a specific asset and return risk assessment"""
    asset_key = asset_id.lower()
    
    if asset_key not in ASSET_DATA:
        return {
            "risk_level": "Unknown",
            "confidence": 0.0,
            "suspicious_activity": [],
            "reasons": ["Asset not found"],
            "actions": []
        }
    
    sample_data = ASSET_DATA[asset_key]
    
    # Call the analyze function from test.py
    result = analyze(sample_data)
    
    # Map to expected format for Streamlit
    return {
        "risk_level": result.get("prediction", "Unknown"),
        "confidence": result.get("confidence", 0.0) / 100.0,  # Convert to 0-1 range
        "suspicious_activity": result.get("suspicious_data_fields", []),
        "reasons": result.get("reasons", []),
        "actions": result.get("remediation", [])
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
