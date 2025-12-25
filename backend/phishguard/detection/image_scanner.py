import cv2
import numpy as np
from PIL import Image
from io import BytesIO
import logging
from phishguard.detection.classify import PhishDetector

class ImageScanner:
    def __init__(self):
        self.detector = PhishDetector()
        self.qr_detector = cv2.QRCodeDetector()
        
    def scan_image(self, file_content: bytes, filename: str) -> dict:
        """
        Analyze image for visual threats (QR codes) and metadata.
        """
        results = {
            "filename": filename,
            "threat_detected": False,
            "qr_codes": [],
            "metadata_suspicious": False,
            "verdict": "SAFE"
        }
        
        try:
            # 1. Load Image
            nparr = np.frombuffer(file_content, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is None:
                return {"error": "Invalid image format"}
                
            # 2. QR Code Detection
            # detectAndDecode returns (retval, decoded_info, points, straight_qrcode)
            # Handling cv2 version differences
            val, points, _ = self.qr_detector.detectAndDecode(img)
            
            if val:
                print(f"QR Code Found: {val}")
                # Analyze function
                scan_result = self.detector.scan_url(val)
                results["qr_codes"].append({
                    "data": val,
                    "scan_result": scan_result
                })
                
                if scan_result["verdict"] in ["PHISHING", "SUSPICIOUS"]:
                    results["threat_detected"] = True
                    results["verdict"] = scan_result["verdict"]
            
            # 3. Simple Metadata Check (Heuristic)
            # e.g. very large or very small files, or specific extensions check
            # For now, just placeholder
            if len(file_content) > 10 * 1024 * 1024: # > 10MB
                results["metadata_suspicious"] = True
                
        except Exception as e:
            logging.error(f"Image scan error: {e}")
            return {"error": str(e)}
            
        if not results["threat_detected"] and results["qr_codes"]:
             # Has QR but safe URL
             results["verdict"] = "CAUTION (QR Found)"
             
        return results
