# Force reload: Map Added
from fastapi import FastAPI, BackgroundTasks, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from phishguard.core.config import settings
from phishguard.core.database import db
from phishguard.detection.classify import PhishDetector
from phishguard.api.security import get_api_key
import os
import datetime

app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

# Mount static files
# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "../../../frontend")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

from phishguard.detection.email_scanner import EmailScanner

detector = PhishDetector()
email_scanner = EmailScanner()

# --- Endpoint Models ---
from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    raw_content: str

@app.on_event("startup")
def startup_db_client():
    db.connect()
    # print(f"INFO:     API Key is active: {settings.API_KEY}")
    pass

@app.on_event("shutdown")
def shutdown_db_client():
    db.close()

@app.get("/")
def read_root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.post("/scan/url")
async def scan_url(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(get_api_key)
):
    result = detector.scan_url(request.url)
    
    # Add timestamp and save to DB
    scan_record = result.copy()
    scan_record["timestamp"] = datetime.datetime.utcnow()
    
    # Save asynchronously
    background_tasks.add_task(save_scan_result, scan_record)
    
    return result

@app.post("/scan/email")
async def scan_email(request: EmailScanRequest, api_key: str = Depends(get_api_key)):
    """
    Analyzes raw email content for headers, keywords, and malicious links.
    """
    result = email_scanner.scan_email(request.raw_content)
    return result

@app.get("/scans/history")
async def get_history(limit: int = 20):
    if db.db is None:
        return []
    
    cursor = db.db.scans.find().sort("timestamp", -1).limit(limit)
    scans = await cursor.to_list(length=limit)
    
    # Serialize ObjectId to string for JSON compatibility
    for scan in scans:
        if "_id" in scan:
            scan["_id"] = str(scan["_id"])
            
    return scans


# Helper function for async saving (defined here to avoid circular imports)
from phishguard.detection.image_scanner import ImageScanner
from fastapi import UploadFile, File

# Initialize Image Scanner
image_scanner = ImageScanner()

# ... existing code ...

@app.post("/scan/image")
async def scan_image(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None, # Make optional to match signature if needed, or just use
    api_key: str = Depends(get_api_key)
):
    contents = await file.read()
    result = image_scanner.scan_image(contents, file.filename)
    
    # Optional: Log image scans to DB (omitted for MVP or added purely as log)
    # if background_tasks:
    #    background_tasks.add_task(log_image_scan, result)
        
    return result

@app.get("/stats/map")
async def get_map_stats():
    """
    Returns a list of recent threat locations (Mocked for demo purposes).
    In a real app, this would query IP geolocation from the DB.
    """
    import random
    
    # Mock Data Generation
    # Generating 50 random points focused around rough coordinates of major tech hubs
    # to simulate "attacks"
    
    locations = []
    
    # Hubs: (Lat, Lng, Variance)
    hubs = [
        (37.7749, -122.4194, 10), # SF/Silicon Valley
        (40.7128, -74.0060, 5),   # NYC
        (51.5074, -0.1278, 5),    # London
        (35.6762, 139.6503, 5),   # Tokyo
        (22.3193, 114.1694, 2),   # Hong Kong
        (55.7558, 37.6173, 10),   # Moscow
        (-33.8688, 151.2093, 5)   # Sydney
    ]
    
    for _ in range(30):
        hub = random.choice(hubs)
        lat = hub[0] + random.uniform(-hub[2], hub[2])
        lng = hub[1] + random.uniform(-hub[2], hub[2])
        
        locations.append({
            "lat": lat,
            "lng": lng,
            "type": "PHISHING" if random.random() > 0.2 else "LEGITIMATE",
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        
    return locations

async def save_scan_result(record: dict):
    if db.db is not None:
        await db.db.scans.insert_one(record)
