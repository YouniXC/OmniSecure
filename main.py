import imaplib
import email
from email.header import decode_header
import re
import time
import requests
import json
import os
import joblib
import hashlib
import cv2
import numpy as np
import glob  # Used for clearing session files
from datetime import datetime
from plyer import notification

# ==========================================
# CONFIGURATION
# ==========================================
# Set to True for testing (alerts every loop). Set to False for production.
TESTING_MODE = False

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
    print("[*] Config loaded.")
except:
    print("[!] Config Error: Missing config.json")
    config = {}

EMAIL_USER = config.get("email_user", "")
EMAIL_PASS = config.get("email_pass", "")
VT_API_KEY = config.get("vt_api_key", "")
CHECK_INTERVAL = config.get("check_interval", 10)
BLOCKED_EXTS = config.get("blocked_extensions", [])
WHITELIST = config.get("whitelisted_domains", [])

# Load from config instead of hardcoding (Defaults to Gmail)
IMAP_SERVER = config.get("imap_server", "imap.gmail.com")

VT_URL_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VT_FILE_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/files"
LOG_FILE = "detector_log.txt"
REPORT_DIR = "reports"
HISTORY_FILE = "scanned_history.json"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

# ==========================================
# SESSION MANAGEMENT
# ==========================================
def clear_session_data():
    """Clears visual logs but KEEPS the scanned_history.json"""
    print("[*] Clearing previous session data...")
    
    # 1. Clear the text log (make it empty)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} System Session Started\n")
    
    # 2. Clear the reports folder (Delete old threat alerts)
    # Be careful: This deletes the JSON files that populate the dashboard table
    files = glob.glob(os.path.join(REPORT_DIR, '*.json'))
    for f in files:
        try:
            os.remove(f)
        except Exception as e:
            print(f"[!] Error deleting {f}: {e}")
            
    # NOTE: We do NOT touch 'scanned_history.json' here.
    # This ensures we don't re-scan old emails.

# ==========================================
# HISTORY MANAGER
# ==========================================
def load_scanned_ids():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f: 
                return set(json.load(f))
        except: 
            return set()
    return set()

def save_scanned_id(uid):
    if TESTING_MODE: return
    ids = load_scanned_ids()
    ids.add(uid)
    with open(HISTORY_FILE, 'w') as f: 
        json.dump(list(ids), f)

# ==========================================
# AI LOADER
# ==========================================
def dummy_tokenizer(x): return x

url_model = None
email_model = None

def load_ai():
    global url_model, email_model
    try:
        url_model = joblib.load("models/url_model.pkl")
        email_model = joblib.load("models/email_model.pkl")
        print("[*] AI Models Loaded.")
    except:
        print("[!] AI Models Missing. Running in limited mode.")
        url_model = None
        email_model = None

# ==========================================
# UTILITIES
# ==========================================
def log_event(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{ts} {msg}"
    print(entry)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

def show_popup_alert(subject, severity, score):
    try:
        notification.notify(
            title=f"[{severity}] Threat Detected!",
            message=f"{subject}\nScore: {score}/100. Check Dashboard.",
            app_name="OmniSecure",
            timeout=10,
            toast=True
        )
    except Exception as e:
        print(f"[!] Notification Failed: {e}")

# ==========================================
# QR CODE SCANNER
# ==========================================
def scan_qr_codes(image_bytes):
    found_urls = []
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img_cv is None: return []

        detector = cv2.QRCodeDetector()
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img_cv)
        
        if retval:
            for data in decoded_info:
                if data:
                    qr_data = str(data)
                    if len(qr_data) > 3:
                        found_urls.append(qr_data)
                        log_event(f"📸 QR Code Detected Data: {qr_data}")
    except Exception as e:
        log_event(f"QR Scan Error: {e}")
        
    return found_urls

# ==========================================
# VT CHECKERS
# ==========================================
def check_vt_url(url):
    if not VT_API_KEY: return False, "No API Key"
    
    headers = {"x-apikey": VT_API_KEY}
    try:
        # 1. Submit URL
        requests.post(VT_URL_SCAN_ENDPOINT, data={"url": url}, headers=headers)
        
        # 2. Get Analysis
        url_id = hashlib.sha256(url.encode()).hexdigest()
        resp = requests.get(f"{VT_URL_SCAN_ENDPOINT}/{url_id}", headers=headers)
        
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            if stats['malicious'] > 0:
                return True, f"Malicious ({stats['malicious']} Vendors)"
    except: 
        pass
        
    return False, "Clean"

def check_vt_hash(file_hash):
    if not VT_API_KEY: return False, "No API Key"
    
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(f"{VT_FILE_SCAN_ENDPOINT}/{file_hash}", headers=headers)
        
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            if stats['malicious'] > 0:
                return True, f"Malicious ({stats['malicious']} Vendors)"
    except: 
        pass
        
    return False, "Clean"

# ==========================================
# SCORING LOGIC
# ==========================================
def calculate_risk(body, urls, attachments, qr_source_urls):
    score = 0
    ai_reasons = []
    vt_reasons = []
    att_verdict = "No Attachments"
    qr_verdict = "No QR Found"
    bad_artifacts = []
    
    unique_urls = list(set(urls))

    # 1. AI Text Scan
    if email_model and body and len(body) > 50:
        try:
            if email_model.predict([body])[0] == 1:
                score += 30
                ai_reasons.append("Suspicious Phishing Language")
        except: pass

    # 2. URL Scan
    if unique_urls:
        if qr_source_urls: qr_verdict = "Clean QR"
        
        for url in unique_urls:
            # CHANGE: Convert to lowercase to ensure Whitelist works 100%
            if any(w.lower() in url.lower() for w in WHITELIST): 
                continue
            
            is_bad_link = False
            
            # VT Check (Hard Evidence)
            is_mal, reason = check_vt_url(url)
            if is_mal:
                score += 100
                is_bad_link = True
                vt_reasons.append(f"VT Malicious: {reason}")
            
            # AI Check (Soft Evidence)
            elif url_model:
                try:
                    if url_model.predict([url])[0] == 1:
                        if score < 70: score += 20
                        is_bad_link = True
                        if url in qr_source_urls:
                            ai_reasons.append("Malicious QR Payload")
                            qr_verdict = "Malicious QR"
                        else:
                            ai_reasons.append("Suspicious URL Pattern")
                except: pass
            
            # Fallback
            if "ngrok" in url or "bit.ly" in url:
                score += 10
                is_bad_link = True
                ai_reasons.append("Suspicious Shortener")
            
            if is_bad_link:
                bad_artifacts.append(f"URL: {url}")

    # 3. Attachment Scan
    for fname, fcontent in attachments:
        ext = os.path.splitext(fname)[1].lower()
        
        if ext in BLOCKED_EXTS:
            score = 100
            att_verdict = f"Blocked Extension ({ext})"
            bad_artifacts.append(f"File: {fname}")
        else:
            fhash = hashlib.sha256(fcontent).hexdigest()
            is_mal, reason = check_vt_hash(fhash)
            if is_mal:
                score = 100
                att_verdict = f"VT Malware: {reason}"
                bad_artifacts.append(f"Hash: {fhash}")

    # Score Normalization
    if not vt_reasons and att_verdict == "No Attachments" and score > 75:
        score = 75
    
    if score > 100: score = 100
    
    if score >= 80: severity = "CRITICAL"
    elif score >= 50: severity = "HIGH"
    elif score >= 20: severity = "MEDIUM"
    else: severity = "LOW"

    ai_verdict = ", ".join(list(set(ai_reasons))) if ai_reasons else "Pass"
    vt_verdict = ", ".join(list(set(vt_reasons))) if vt_reasons else "Pass"

    return {
        "score": score,
        "severity": severity,
        "ai_verdict": ai_verdict,
        "vt_verdict": vt_verdict,
        "att_verdict": att_verdict,
        "qr_verdict": qr_verdict,
        "bad_artifacts": list(set(bad_artifacts)),
        "action": "Detected"
    }

# ==========================================
# SAVE LOG
# ==========================================
def save_threat_log(email_data, threat_data):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_subject = "".join([c for c in email_data.get('subject', 'Unknown') if c.isalnum() or c in (' ', '-', '_')]).strip()[:30]
    filename = f"Threat_{safe_subject}_{ts}"
    json_path = os.path.join(REPORT_DIR, f"{filename}.json")
    
    report_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subject": email_data['subject'],
        "sender": email_data['sender'],
        "body_snippet": email_data.get('body', '')[:2000],
        "score": threat_data['score'],
        "severity": threat_data['severity'],
        "action": threat_data['action'],
        "ai_verdict": threat_data['ai_verdict'],
        "vt_verdict": threat_data['vt_verdict'],
        "att_verdict": threat_data['att_verdict'],
        "qr_verdict": threat_data['qr_verdict'],
        "bad_artifacts": threat_data['bad_artifacts'],
        "details": f"{threat_data['ai_verdict']} | {threat_data['qr_verdict']}",
    }
    
    with open(json_path, 'w') as f: 
        json.dump(report_data, f)

# ==========================================
# MAIN ENGINE
# ==========================================
def start_engine():
    print("\n--- Scanning Cycle ---")
    if not url_model: load_ai()
    
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("INBOX")
        
        status, messages = mail.uid('search', None, 'UNSEEN')
        uids = messages[0].split()
        
        scanned_history = load_scanned_ids()
        
        if not uids:
            print(" [*] No new emails.")
            
        for uid_byte in uids:
            uid = uid_byte.decode('utf-8')
            
            if not TESTING_MODE and uid in scanned_history:
                continue
                
            # Use PEEK to avoid marking the email as Read (keep it Bold in Gmail)
            res, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[])')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = decode_header(msg["Subject"])[0][0]
                    if isinstance(subject, bytes): subject = subject.decode()
                    
                    sender = msg.get("From")
                    log_event(f"Scanning: {subject}")
                    
                    if any(w in sender for w in WHITELIST):
                        save_scanned_id(uid)
                        continue
                    
                    # Extraction Phase
                    body = ""
                    urls = []
                    attachments = []
                    qr_source_urls = []
                    
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        disposition = str(part.get("Content-Disposition"))
                        
                        if "text/plain" in content_type and "attachment" not in disposition:
                            text = part.get_payload(decode=True).decode(errors='ignore')
                            body += text
                            # Regex to find URLs
                            urls += re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
                        
                        if "image" in content_type or "attachment" in disposition:
                            fname = part.get_filename()
                            payload = part.get_payload(decode=True)
                            
                            if payload:
                                if "image" in content_type or (fname and fname.lower().endswith(('.png', '.jpg', '.jpeg'))):
                                    img_urls = scan_qr_codes(payload)
                                    if img_urls:
                                        log_event(f"Found QR Code Links: {img_urls}")
                                        urls += img_urls
                                        qr_source_urls += img_urls
                                        
                                if fname:
                                    attachments.append((fname, payload))
                    
                    # Risk Analysis
                    threat_data = calculate_risk(body, urls, attachments, qr_source_urls)
                    
                    if threat_data['score'] > 0:
                        log_event(f"⚠️ THREAT DETECTED: Score {threat_data['score']}")
                        
                        # 1. ALWAYS LOG to dashboard (so you have history)
                        save_threat_log({
                            "subject": subject,
                            "sender": sender, 
                            "body": body
                        }, threat_data)

                        # 2. ONLY NOTIFY if Score >= 50 (High/Critical)
                        if threat_data['score'] >= 50:
                            show_popup_alert(subject, threat_data['severity'], threat_data['score'])
                    else:
                        log_event("Clean.")
                        
                    save_scanned_id(uid)
                    
        mail.close()
        mail.logout()
        
    except Exception as e:
        log_event(f"Error: {e}")

if __name__ == "__main__":
    # --- CLEARS OLD DASHBOARD LOGS ON STARTUP ---
    clear_session_data()
    # --------------------------------------------
    
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} System Started\n")
        
    while True:
        start_engine()
        time.sleep(CHECK_INTERVAL)