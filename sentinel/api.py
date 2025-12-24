# sentinel/api.py
from fastapi import FastAPI
from pydantic import BaseModel
from sentinel.scanner import scan_text

app = FastAPI(title="SentinelSecrets API")

class ScanRequest(BaseModel):
    content: str

@app.post("/scan")
def scan(req: ScanRequest):
    return {"findings": scan_text(req.content)}
