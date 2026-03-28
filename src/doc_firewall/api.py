from fastapi import FastAPI, File, UploadFile, Query, HTTPException
from fastapi.responses import JSONResponse
import tempfile
import os
import shutil
from typing import Optional

from .scanner import Scanner
from .config import ScanConfig

app = FastAPI(
    title="DocFirewall Microservice",
    description="Drop-in REST API wrapper for DocFirewall zero-trust document scanning.",
    version="0.3.0"
)

@app.post("/scan")
async def scan_document(
    file: UploadFile = File(...),
    profile: str = Query("balanced", description="Threshold profile: lenient, balanced, or strict"),
    enable_ml: bool = Query(False, description="Enable local deep learning and heuristics")
):
    try:
        config = ScanConfig(profile=profile)
        if enable_ml:
            config.enable_advanced_ahocorasick = True
            config.enable_advanced_bert = True
            config.enable_advanced_tfidf = True
            config.enable_credential_entropy = True
            
        scanner = Scanner(config=config)

        # Create a temporary file to save the upload
        suffix = os.path.splitext(file.filename)[1] if file.filename else ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name

        try:
            report = scanner.scan_sync(tmp_path)
            # return standard formatted output
            return JSONResponse(status_code=200, content=report.to_dict())
        finally:
            # Reclaim temp file storage
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
