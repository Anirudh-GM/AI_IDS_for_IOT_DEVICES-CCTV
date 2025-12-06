# app.py — Enhanced version with better error handling and features
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for, flash, send_from_directory, has_request_context
import cv2
import numpy as np
import time
import logging
import os
import threading
import socket
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import json
import hashlib
import re
from threading import Lock
from functools import wraps
import uuid
from email.mime.text import MIMEText
import smtplib
import random
from dotenv import load_dotenv

# Set up logging first
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Video-based AI features disabled - focusing on network-based IDS only
AI_ENABLED = False
get_ai_engine = None

# Import comprehensive attack detection
try:
    from attack_detection_module import get_attack_detector, get_network_attack_detector
    ATTACK_DETECTION_ENABLED = True
    logger.info("Attack Detection Module loaded successfully")
except ImportError as e:
    ATTACK_DETECTION_ENABLED = False
    logger.warning(f"Attack Detection Module not available: {e}")
    get_attack_detector = None
    get_network_attack_detector = None

# Import attack recovery module
try:
    from attack_recovery_module import get_recovery_manager
    RECOVERY_ENABLED = True
    logger.info("Attack Recovery Module loaded successfully")
except ImportError as e:
    RECOVERY_ENABLED = False
    logger.warning(f"Attack Recovery Module not available: {e}")
    get_recovery_manager = None

# Load environment variables from .env file (explicitly use .env in current directory)
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=env_path, override=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Import Network IDS Module (after app is created)
try:
    from network_ids_routes import network_ids_bp
    from network_ids_module import get_network_ids
    app.register_blueprint(network_ids_bp)
    NETWORK_IDS_ENABLED = True
    logger.info("Network IDS routes registered successfully")
except ImportError as e:
    NETWORK_IDS_ENABLED = False
    logger.warning(f"Network IDS routes not available: {e}")
    get_network_ids = None

# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY', 'ai-ids-secret-key-change-in-production')

# Session configuration
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=24)  # Session expires after 24 hours

# Configuration
class Config:
    CAMERA_INDEX = 0
    FRAME_WIDTH = 640
    FRAME_HEIGHT = 480
    FPS = 60  # Target FPS for video streaming (increased for faster response)
    OBSTRUCTION_THRESHOLD = 0.85
    MOTION_THRESHOLD = 0.3
    
    # Email Configuration (loaded from .env file)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('GMAIL_EMAIL', '')  # Sender email from .env
    MAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD', '')  # App password from .env
    
    # CCTV Recording Configuration
    RECORDINGS_DIR = "recordings"
    VIDEO_DURATION = 300  # 5 minutes per video file (seconds)
    VIDEO_CODEC = 'MJPG'  # More reliable than XVID, no timestamp issues
    VIDEO_FPS = 20
    MOTION_DIFF_THRESHOLD = int(os.getenv("MOTION_DIFF_THRESHOLD", "2500"))
    BRIGHTNESS_LOW = int(os.getenv("BRIGHTNESS_LOW", "25"))
    COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))
    ALERT_PHONE = os.getenv("ALERT_PHONE", "")
    UPLOAD_FOLDER = 'static/events'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    # Notification settings

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.RECORDINGS_DIR, exist_ok=True)

# User database (in production, use a proper database)
USERS = {
    'admin': {
        'password': 'admin123',  # In production, use hashed passwords
        'email': 'admin@ai-ids.local',
        'role': 'Administrator',
        'member_since': '2024-01-01'
    },
    'security': {
        'password': 'security123',
        'email': 'security@ai-ids.local',
        'role': 'Security Officer',
        'member_since': '2024-01-15'
    }
}

# Generate and store admin codes
ADMIN_CODES = {}
def generate_admin_code():
    """Generate a unique 4-digit admin code"""
    import random
    while True:
        code = f"{random.randint(1000, 9999)}"
        if code not in ADMIN_CODES:
            ADMIN_CODES[code] = time.time()  # Store timestamp
            return code

# Initialize with one admin code
INITIAL_ADMIN_CODE = "1234"  # Default code for first setup
ADMIN_CODES[INITIAL_ADMIN_CODE] = time.time()

# Store OTPs and their expiration times
OTP_STORAGE = {}
# Store admin code attempts
ADMIN_CODE_ATTEMPTS = {}
# Store locked out IPs and their unlock times
LOCKED_OUT_IPS = {}

# Constants
MAX_ADMIN_ATTEMPTS = 3
LOCKOUT_DURATION = 3  # seconds (changed from 30 for testing)
OTP_EXPIRY = 300  # 5 minutes

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_users():
    """Load users from JSON file"""
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Create default admin user if file doesn't exist
        default_users = {
            "admin": {
                "username": "admin",
                "email": "admin@example.com",
                "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # password: password
                "role": "admin",
                "created_at": datetime.now().isoformat()
            }
        }
        with open('users.json', 'w') as f:
            json.dump(default_users, f, indent=4)
        return default_users

def authenticate_user(username, password):
    """Authenticate user credentials with hashed password"""
    users = load_users()
    user = users.get(username)
    if user:
        # Hash the provided password for comparison
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if user['password'] == hashed_password:
            return user
    return None

def get_user_by_username(username):
    """Get user information by username"""
    users = load_users()
    return users.get(username)

def get_alert_email():
    """Get alert email from database """
    # Try to get current logged-in user's email first
    if 'username' in session:
        username = session.get('username')
        users = load_users()
        if username in users and users[username].get('email'):
            return users[username]['email']
    
    # Fallback to first available admin user's email
    users = load_users()
    for username, user_data in users.items():
        if user_data.get('email'):
            return user_data['email']
    
    # No email found
    return None

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def is_ip_locked_out(ip):
    """Check if IP is currently locked out"""
    if ip in LOCKED_OUT_IPS:
        if time.time() < LOCKED_OUT_IPS[ip]:
            return True
        else:
            del LOCKED_OUT_IPS[ip]
    return False

def send_otp_email(email, otp):
    """Send OTP to the provided email"""
    try:
        # Log OTP to console for testing
        print(f"\n{'='*50}")
        print(f"OTP GENERATED FOR TESTING")
        print(f"Email: {email}")
        print(f"OTP: {otp}")
        print(f"{'='*50}\n")
        
        # Require valid mail config
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            logger.error("Email sending failed: MAIL_USERNAME or MAIL_PASSWORD not configured")
            return False

        msg = MIMEText(f'Your OTP is: {otp}\n\nThis OTP is valid for 5 minutes.')
        msg['Subject'] = 'Your Verification Code'
        msg['From'] = Config.MAIL_USERNAME
        msg['To'] = email
        
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10) as server:
            server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")
        return False

def load_logs_from_file():
    """Load logs from persistent storage file"""
    logs_file = "logs.json"
    try:
        if os.path.exists(logs_file):
            with open(logs_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
                # Ensure logs is a list
                if not isinstance(logs, list):
                    logs = []
                return logs
        return []
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading logs from file: {e}")
        return []

def save_logs_to_file(logs):
    """Save logs to persistent storage file"""
    logs_file = "logs.json"
    try:
        # Ensure logs is a list
        if not isinstance(logs, list):
            logger.warning("Logs is not a list, converting...")
            logs = list(logs) if logs else []
        
        # Remove duplicates by ID
        seen_ids = set()
        unique_logs = []
        for log in logs:
            log_id = log.get('id')
            if log_id and log_id not in seen_ids:
                seen_ids.add(log_id)
                unique_logs.append(log)
            elif not log_id:
                # Keep logs without IDs (legacy support)
                unique_logs.append(log)
        
        # Keep only last 10000 entries to prevent file from growing too large
        logs_to_save = unique_logs[-10000:] if len(unique_logs) > 10000 else unique_logs
        
        # Sort by timestamp for consistency
        logs_to_save.sort(key=lambda x: x.get('timestamp', x.get('time', '')), reverse=False)
        
        # Write to file with atomic operation (write to temp file first, then rename)
        temp_file = logs_file + '.tmp'
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(logs_to_save, f, indent=2, ensure_ascii=False)
        
        # Atomic rename (works on Windows too)
        if os.path.exists(logs_file):
            os.replace(temp_file, logs_file)
        else:
            os.rename(temp_file, logs_file)
        
        logger.debug(f"Saved {len(logs_to_save)} logs to {logs_file}")
    except IOError as e:
        logger.error(f"Error saving logs to file: {e}", exc_info=True)
        # Try to clean up temp file if it exists
        try:
            if os.path.exists(logs_file + '.tmp'):
                os.remove(logs_file + '.tmp')
        except:
            pass
    except Exception as e:
        logger.error(f"Unexpected error saving logs: {e}", exc_info=True)

def log_event(event_type, reason, session_id=None, session_data=None, client_ip=None, username=None):
    """Log an event with timestamp and optional session data"""
    timestamp = datetime.now()
    entry_id = str(uuid.uuid4())  # Generate unique ID for each log entry
    entry = {
        "id": entry_id,
        "timestamp": timestamp.isoformat(),
        "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),  # Human-readable time
        "event_type": event_type,
        "reason": reason
    }
    
    # Add client IP if provided
    if client_ip:
        entry["client_ip"] = client_ip
    
    # Add username if provided
    if username:
        entry["username"] = username
    
    # Add session data if provided
    if session_id:
        entry["session_id"] = session_id
    if session_data:
        entry["session_data"] = session_data
    
    # Log to the application log
    logger.info(f"Event: {event_type} - {reason}")
    
    # Important events that should trigger notifications
    important_events = [
        'ALERT', 
        'OBSTRUCTION_DETECTED', 
        'MANUAL_ATTACK_TRIGGER', 
        'INJECT_ATTACK_TRIGGER',  # Immediate notification when attack starts
        'INJECT_ATTACK_SESSION',  # Session summary after attack ends
        'MOTION_DETECTED',
        'INTRUSION_DETECTED',
        'SYSTEM_ALERT',
        'SECURITY_ALERT',
        # Network Attack Types
        'DDOS',                    # DDoS Flood Attack
        'DOS_FLOOD',               # DoS Flood Attack
        'PORT_SCAN',               # Port Scan / Reconnaissance
        'BRUTE_FORCE',             # Brute Force Attack
        'BRUTE_FORCE_ATTEMPT',     # Brute Force Attempt
        'UNAUTHORIZED_ACCESS',     # Unauthorized Access
        'WEB_EXPLOIT',             # Web Exploit (SQL Injection, XSS, etc.)
        'AI_NETWORK_ATTACK',       # AI-detected Network Attack
        # CCTV Attack Types
        'VIDEO_INJECTION',         # Video Injection Attack
        'FRAME_FREEZE',            # Frame Freeze Attack
        'MOTION_MASKING',          # Motion Masking Attack
        'CABLE_CUTTING',           # Cable Cutting Attack
        # Other Security Events
        'SYSTEM_TAMPERING',        # System Tampering
        'CONFIG_INJECTION',        # Configuration Injection
        'CREDENTIAL_THEFT',        # Credential Theft Attempt
        'EXPLOIT_ATTEMPT',         # Exploit Attempt
        'RECONNAISSANCE',          # Reconnaissance Activity
        'SUSPICIOUS_ACTIVITY'      # General Suspicious Activity
    ]
    
    is_important_event = any(event in event_type for event in important_events)
    
    # Send email notification for important events
    if is_important_event:
        try:
            # Prepare email notification
            subject = f"🔔 AI-IDS {event_type}"
            body = f"""
            <h2>AI-IDS Security Alert</h2>
            <p><strong>Event Type:</strong> {event_type}</p>
            <p><strong>Time:</strong> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Details:</strong> {reason}</p>
            """
            
            # Add session data if available
            if session_data:
                body += "<p><strong>Session Data:</strong></p><pre>"
                body += json.dumps(session_data, indent=2)
                body += "</pre>"
            
            # Send email
            msg = MIMEText(body, 'html')
            msg['Subject'] = subject
            msg['From'] = Config.MAIL_USERNAME
            
            # Determine recipient email based on provided username or session
            recipient_email = None
            if username:
                users = load_users()
                user_data = users.get(username)
                if user_data and user_data.get('email'):
                    recipient_email = user_data['email']
            elif has_request_context() and 'username' in session: # Fallback to session if available
                try:
                    current_session_username = session.get('username')
                    users = load_users()
                    user_data = users.get(current_session_username)
                    if user_data and user_data.get('email'):
                        recipient_email = user_data['email']
                except RuntimeError:
                    # Session not available in this context
                    pass
            
            # If no specific user email found, try to send to admins for important security events
            if not recipient_email and is_important_event:
                users = load_users()
                # Find first admin user with email
                for user_name, user_data in users.items():
                    user_role = user_data.get('role', '').lower()
                    if (user_role == 'administrator' or user_role == 'admin') and user_data.get('email'):
                        recipient_email = user_data['email']
                        logger.info(f"No specific user email found, sending to admin: {user_name}")
                        break
                # If still no admin found, try any user with email
                if not recipient_email:
                    for user_name, user_data in users.items():
                        if user_data.get('email'):
                            recipient_email = user_data['email']
                            logger.info(f"No admin email found, sending to user: {user_name}")
                            break
            
            # Skip sending email if no recipient is found
            if not recipient_email:
                logger.warning(f"No recipient email found for event {event_type} - email not sent")
                return entry
            
            msg['To'] = recipient_email
            
            with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10) as server:
                server.starttls()
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.send_message(msg)
                
            logger.info(f"Email alert sent for event: {event_type} to {recipient_email}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
    
    # Add to in-memory detection log (for quick access, keeps last 1000 events)
    detection_log.append(entry)
    if len(detection_log) > 1000:
        detection_log.pop(0)
    
    # Save to persistent storage (with error handling and retry)
    try:
        all_logs = load_logs_from_file()
        # Ensure all_logs is a list
        if not isinstance(all_logs, list):
            all_logs = []
        # Check if entry already exists (by ID) to prevent duplicates
        existing_ids = {log.get('id') for log in all_logs if log.get('id')}
        if entry.get('id') not in existing_ids:
            all_logs.append(entry)
            # Keep only last 10000 entries to prevent file from growing too large
            if len(all_logs) > 10000:
                all_logs = all_logs[-10000:]
            save_logs_to_file(all_logs)
            logger.debug(f"Log saved: {entry.get('event_type')} - {entry.get('id')}")
        else:
            logger.debug(f"Log already exists, skipping: {entry.get('id')}")
    except Exception as e:
        logger.error(f"Error saving log to persistent storage: {e}", exc_info=True)
        # Try to save at least to in-memory log even if file save fails
    
    return entry

# Network traffic feature extraction for AI analysis
def extract_network_features(request, start_time=None):
    """
    Extract network traffic features from Flask request for AI analysis
    Maps HTTP request properties to NSL-KDD-like features
    """
    if start_time is None:
        start_time = time.time()
    
    # Calculate duration (request processing time)
    duration = time.time() - start_time
    
    # Extract request properties
    method = request.method
    path = request.path
    endpoint = path.split('/')[-1] if path else ''
    
    # Map HTTP method to protocol type (simplified)
    protocol_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 4}
    protocol_type = protocol_map.get(method, 0)
    
    # Map endpoint to service type (simplified)
    service_map = {
        'login': 0, 'api': 1, 'status': 2, 'control': 3, 'video_feed': 4,
        'dashboard': 5, 'profile': 6, 'static': 7, 'favicon': 8
    }
    service = 0
    for key, val in service_map.items():
        if key in path.lower():
            service = val
            break
    
    # Extract request size
    content_length = request.content_length or 0
    src_bytes = content_length  # Bytes sent by client
    dst_bytes = len(str(request.get_data())) if request.get_data() else 0  # Bytes received
    
    # Extract headers and flags
    connection = request.headers.get('Connection', '').lower()
    flag = 1 if 'keep-alive' in connection else 0
    
    # Extract query parameters and payload
    query_string = str(request.query_string) if request.query_string else ''
    payload = str(request.get_data()) if request.get_data() else ''
    
    # Calculate features based on request patterns
    num_failed_logins = 0  # Will be updated by login handler
    logged_in = 1 if has_request_context() and 'username' in session else 0
    is_guest_login = 1 if logged_in == 0 else 0
    is_host_login = 1 if logged_in == 1 else 0
    
    # Count suspicious patterns in payload
    suspicious_patterns = ['<script', 'union select', 'drop table', '../', 'exec(', 'eval(']
    num_shells = sum(1 for pattern in suspicious_patterns if pattern.lower() in payload.lower())
    num_access_files = 1 if '../' in path or '..' in path else 0
    
    # Request frequency features (simplified - would need history tracking)
    count = 1  # Current request count
    srv_count = 1  # Service count
    
    # Error rates (simplified)
    serror_rate = 0.0
    srv_serror_rate = 0.0
    rerror_rate = 0.0
    srv_rerror_rate = 0.0
    
    # Service rates (simplified)
    same_srv_rate = 1.0
    diff_srv_rate = 0.0
    srv_diff_host_rate = 0.0
    
    # Host-based features (simplified)
    dst_host_count = 1
    dst_host_srv_count = 1
    dst_host_same_srv_rate = 1.0
    dst_host_diff_srv_rate = 0.0
    dst_host_same_src_port_rate = 1.0
    dst_host_srv_diff_host_rate = 0.0
    dst_host_serror_rate = 0.0
    dst_host_srv_serror_rate = 0.0
    dst_host_rerror_rate = 0.0
    dst_host_srv_rerror_rate = 0.0
    
    # Build feature dictionary matching NSL-KDD format
    features = {
        'duration': duration,
        'protocol_type': protocol_type,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': 0,  # Not applicable for HTTP
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': num_shells,  # Suspicious patterns
        'num_failed_logins': num_failed_logins,
        'logged_in': logged_in,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': num_shells,
        'num_access_files': num_access_files,
        'num_outbound_cmds': 0,
        'is_host_login': is_host_login,
        'is_guest_login': is_guest_login,
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': srv_serror_rate,
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': srv_rerror_rate,
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'srv_diff_host_rate': srv_diff_host_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
        'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
        'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
        'dst_host_rerror_rate': dst_host_rerror_rate,
        'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate
    }
    
    return features

# Flask before_request hook for automatic AI network traffic analysis
@app.before_request
def analyze_network_traffic_ai():
    """
    Automatically analyze all incoming network traffic using AI/ML models
    Runs before every request to detect attacks in real-time
    """
    # Skip analysis for static files and favicon
    if request.path.startswith('/static/') or request.path == '/favicon.ico':
        return None
    
    # Skip analysis for network IDS API endpoints (to avoid recursion)
    if request.path.startswith('/api/network-ids/'):
        return None
    
    # IMMEDIATE MITIGATION: Check if IP is blocked and reject request immediately
    client_ip = request.remote_addr
    if RECOVERY_ENABLED and get_recovery_manager:
        recovery_manager = get_recovery_manager()
        if recovery_manager.is_ip_blocked(client_ip):
            logger.warning(f"🚫 Blocked IP {client_ip} attempted to access {request.path} - request rejected")
            return jsonify({
                "error": "Access denied",
                "message": "Your IP address has been temporarily blocked due to suspicious activity",
                "status": 403
            }), 403
    
    # Network Attack Detection for ALL requests (DDoS, Port Scan, etc.)
    request_time = time.time()
    
    if ATTACK_DETECTION_ENABLED and get_network_attack_detector:
        try:
            network_detector = get_network_attack_detector()
            
            # Detect DoS Flood (for all requests)
            dos_detected, dos_confidence, dos_details = network_detector.detect_dos_flood(client_ip, request_time)
            if dos_detected and dos_confidence > 0.85:
                log_event("DOS_FLOOD", dos_details, client_ip=client_ip, username=session.get('username') if has_request_context() and 'username' in session else None)
                # IMMEDIATE MITIGATION: Block IP and stop attack immediately
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    # Record attack start (this will block the IP immediately)
                    recovery_manager.record_attack_start("DOS_FLOOD", client_ip, dos_details, duration=None)
                    # Immediately end the attack since it's being blocked
                    recovery_manager.record_attack_end("DOS_FLOOD", client_ip)
                    logger.warning(f"🛡️  DDoS attack from {client_ip} detected and blocked immediately")
            
            # Detect Port Scan
            port = request.environ.get('SERVER_PORT', 5000)
            endpoint = request.path
            scan_detected, scan_confidence, scan_details = network_detector.detect_port_scan(client_ip, port, endpoint)
            if scan_detected and scan_confidence > 0.85:
                log_event("PORT_SCAN", scan_details, client_ip=client_ip, username=session.get('username') if has_request_context() and 'username' in session else None)
                # IMMEDIATE MITIGATION: Block IP and stop attack immediately
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    # Record attack start (this will block the IP immediately)
                    recovery_manager.record_attack_start("PORT_SCAN", client_ip, scan_details, duration=None)
                    # Immediately end the attack since it's being blocked
                    recovery_manager.record_attack_end("PORT_SCAN", client_ip)
                    logger.warning(f"🛡️  Port scan from {client_ip} detected and blocked immediately")
        except Exception as e:
            logger.error(f"Error in network attack detection: {e}", exc_info=True)
    
    # Check if Network IDS is available and trained
    if not NETWORK_IDS_ENABLED or get_network_ids is None:
        return None
    
    try:
        network_ids = get_network_ids()
        
        # Only analyze if model is trained
        if not network_ids.is_trained:
            return None
        
        # Extract network features from request
        request_start_time = time.time()
        features = extract_network_features(request, request_start_time)
        
        # Analyze using AI model
        result = network_ids.analyze_network_traffic(features)
        
        # Check if attack detected
        if result.get('prediction') == 'attack' and result.get('confidence', 0) > 0.7:
            client_ip = request.remote_addr
            confidence = result.get('confidence', 0)
            details = f"AI-IDS detected malicious network traffic: {result.get('prediction')} (confidence: {confidence:.2f})"
            
            # Log the attack
            log_event(
                "AI_NETWORK_ATTACK",
                details,
                client_ip=client_ip,
                username=session.get('username') if has_request_context() and 'username' in session else None
            )
            
            logger.warning(f"🚨 AI-IDS Attack Detected: {details} from {client_ip}")
        
    except Exception as e:
        # Don't block requests if AI analysis fails
        logger.debug(f"Error in AI network traffic analysis: {e}")
    
    return None

# Global variables
USERS = load_users()
camera = None
frame_lock = Lock()
current_frame = None
detection_log = []
# Load existing logs from persistent storage on startup
try:
    detection_log = load_logs_from_file()
    # Keep only last 1000 in memory for quick access
    if len(detection_log) > 1000:
        detection_log = detection_log[-1000:]
    logger.info(f"Loaded {len(detection_log)} logs from persistent storage")
except Exception as e:
    logger.error(f"Error loading logs on startup: {e}")
    detection_log = []
video_writer = None
video_start_time = None
frame_count = 0
recording_enabled = False  # Temporarily disabled to prevent crashes
last_recording_restart = 0  # Track last restart time
recording_restart_count = 0  # Count restart attempts
runtime = {
    "detection_enabled": True,
    "manual_attack": False,
    "status": "Initializing",
    "last_alert_time": None,
    "camera_connected": False,
    "obstruction_start_time": None,
    "obstruction_notified": False,
    "sound_alert_played": False,
    "sound_active": False,
    "obstruction_session_id": None,
    "session_logged": False,
    "manual_attack_start_time": None,
    "manual_attack_session_id": None,
    "manual_attack_logged": False,
    "manual_attack_username": None,
    "inject_enabled": False,
    "inject_attack_start_time": None,
    "inject_attack_session_id": None,
    "inject_attack_logged": False,
    "inject_attack_username": None,
    "video_injection_detected": False,  # Track if video injection was already detected
    "video_injection_last_logged": None,  # Track last time video injection was logged
}

# Camera management
def init_camera():
    global camera, runtime
    # Release existing camera if any
    if camera is not None:
        try:
            camera.release()
        except:
            pass
        camera = None
    
    # Try different backends and camera indices
    backends_to_try = [
        (cv2.CAP_DSHOW, "DirectShow (Windows)"),
        (cv2.CAP_ANY, "Any available"),
    ]
    
    camera_indices_to_try = [Config.CAMERA_INDEX, 0, 1, 2]
    
    for camera_idx in camera_indices_to_try:
        for backend, backend_name in backends_to_try:
            try:
                logger.info(f"Attempting to open camera {camera_idx} using {backend_name}...")
                camera = cv2.VideoCapture(camera_idx, backend)
                
                if camera.isOpened():
                    # Optimize camera settings for faster frame rate
                    camera.set(cv2.CAP_PROP_FRAME_WIDTH, Config.FRAME_WIDTH)
                    camera.set(cv2.CAP_PROP_FRAME_HEIGHT, Config.FRAME_HEIGHT)
                    camera.set(cv2.CAP_PROP_FPS, Config.FPS)
                    camera.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # Minimal buffer for lower latency
                    
                    # Test if we can actually read a frame
                    ret, test_frame = camera.read()
                    if ret and test_frame is not None:
                        runtime["camera_connected"] = True
                        runtime["status"] = "Running"
                        logger.info(f"✓ Camera {camera_idx} initialized successfully using {backend_name}")
                        # Update config to use the working camera index
                        Config.CAMERA_INDEX = camera_idx
                        return True
                    else:
                        logger.warning(f"Camera {camera_idx} opened but cannot read frames")
                        camera.release()
                        camera = None
                else:
                    if camera is not None:
                        camera.release()
                        camera = None
            except Exception as e:
                logger.warning(f"Failed to open camera {camera_idx} with {backend_name}: {str(e)}")
                if camera is not None:
                    try:
                        camera.release()
                    except:
                        pass
                    camera = None
                continue
    
    logger.error(f"Failed to initialize any camera. Tried indices: {camera_indices_to_try}")
    runtime["camera_connected"] = False
    runtime["status"] = "Camera Not Available"
    return False

def release_camera():
    global camera, runtime, video_writer
    if camera is not None:
        camera.release()
        runtime["camera_connected"] = False
        runtime["status"] = "Camera Disconnected"
        logger.info("Camera released")
    
    # Stop recording
    if video_writer is not None:
        video_writer.release()
        video_writer = None
        logger.info("Video recording stopped")

def start_new_recording():
    """Start a new video recording file"""
    global video_writer, video_start_time, frame_count, last_recording_restart, recording_restart_count
    
    # Rate limit restart attempts (max 5 restarts per minute)
    current_time = time.time()
    if current_time - last_recording_restart < 60:  # Within 1 minute
        if recording_restart_count >= 5:
            logger.warning("Too many recording restart attempts, disabling recording for 5 minutes")
            recording_enabled = False
            # Re-enable after 5 minutes
            threading.Timer(300, lambda: globals().update({'recording_enabled': True, 'recording_restart_count': 0})).start()
            return None
        recording_restart_count += 1
    else:
        # Reset counter if more than 1 minute has passed
        recording_restart_count = 1
    
    last_recording_restart = current_time
    
    # Stop existing recording
    if video_writer is not None:
        try:
            video_writer.release()
        except Exception as e:
            logger.warning(f"Error releasing video writer: {str(e)}")
    
    # Create new video file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cctv_{timestamp}.avi"  # Use AVI format to avoid MP4 timestamp issues
    filepath = os.path.join(Config.RECORDINGS_DIR, filename)
    
    try:
        # Initialize video writer with MJPG codec 
        fourcc = cv2.VideoWriter_fourcc(*'MJPG')
        video_writer = cv2.VideoWriter(
            filepath, 
            fourcc, 
            Config.VIDEO_FPS, 
            (Config.FRAME_WIDTH, Config.FRAME_HEIGHT),
            isColor=True
        )
        
        # Verify video writer was initialized successfully
        if not video_writer.isOpened():
            raise Exception("Failed to initialize video writer")
        
        # Reset frame counter
        frame_count = 0
        video_start_time = time.time()
        logger.info(f"Started new recording: {filename}")
        return filepath
        
    except Exception as e:
        logger.error(f"Failed to start new recording: {str(e)}")
        video_writer = None
        return None

def stop_recording():
    """Stop current video recording"""
    global video_writer, video_start_time
    
    if video_writer is not None:
        video_writer.release()
        video_writer = None
        video_start_time = None
        logger.info("Video recording stopped")
        return True
    return False

def write_frame_to_video(frame):
    """Write frame to current video file with alert overlay"""
    global video_writer, video_start_time, frame_count, recording_enabled
    
    if not recording_enabled or video_writer is None:
        return
    
    # Validate frame before writing
    if frame is None or frame.size == 0:
        logger.warning("Invalid frame received, skipping video write")
        return
    
    # Check video writer state
    if not video_writer.isOpened():
        logger.warning("Video writer is not open, attempting to reopen")
        start_new_recording()
        return
    
    try:
        # Write frame to video
        video_writer.write(frame)
        frame_count += 1
        
        # Log frame write every 100 frames for debugging
        if frame_count % 100 == 0:
            logger.info(f"Written {frame_count} frames to video")
        
        # Check if video duration exceeded
        current_time = time.time()
        if video_start_time and (current_time - video_start_time) >= Config.VIDEO_DURATION:
            # Start new recording file
            start_new_recording()
            
    except Exception as e:
        logger.error(f"Error writing frame to video: {str(e)}")
        # Check if it's an FFmpeg timestamp error
        if "Invalid pts" in str(e) or "avcodec_send_frame" in str(e):
            logger.warning("FFmpeg timestamp error detected, restarting recording")
            start_new_recording()
        else:
            # Try to recover by starting a new recording
            try:
                start_new_recording()
            except Exception as recovery_error:
                logger.error(f"Failed to recover video recording: {str(recovery_error)}")
                # Disable recording temporarily to prevent continuous errors
                recording_enabled = False
                logger.warning("Recording disabled due to persistent errors")

# Routes
@app.route('/')
def index():
    # Always redirect to login as default entry point
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('start_dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        
        if not username or not password:
            return jsonify({
                "success": False,
                "message": "Username and password are required"
            }), 400
        
        # Reload users to get the latest data
        global USERS
        USERS = load_users()
        
        # Authenticate user
        user = authenticate_user(username, password)
        if user:
            # Set session
            session['user_id'] = user['username']
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user.get('role', 'user')
            session.permanent = remember_me
            
            logger.info(f"User logged in: {username}")
            log_event("LOGIN", f"User {username} logged in", client_ip=request.remote_addr, username=username)
            
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": {
                    "username": user['username'],
                    "email": user['email'],
                    "role": user.get('role', 'user')
                },
                "camera_initialized": runtime.get("camera_connected", False)
            })
        else:
            logger.warning(f"Login failed for: {username}")
            client_ip = request.remote_addr
            
            # Track failed login attempts for unauthorized access detection
            if not hasattr(login, 'failed_attempts'):
                login.failed_attempts = {}
            
            if client_ip not in login.failed_attempts:
                login.failed_attempts[client_ip] = 0
            login.failed_attempts[client_ip] += 1
            
            # Update network features for AI analysis (if Network IDS is available)
            if NETWORK_IDS_ENABLED and get_network_ids:
                try:
                    network_ids = get_network_ids()
                    if network_ids.is_trained:
                        # Update failed login count in feature extraction context
                        # This will be used in next request analysis
                        pass  # Feature extraction handles this dynamically
                except:
                    pass
            
            # Detect unauthorized access attempts
            if ATTACK_DETECTION_ENABLED and get_network_attack_detector:
                try:
                    network_detector = get_network_attack_detector()
                    unauthorized_detected, unauthorized_confidence, unauthorized_details = network_detector.detect_unauthorized_access(
                        client_ip, login.failed_attempts[client_ip], False
                    )
                    if unauthorized_detected and unauthorized_confidence > 0.7:
                        log_event("UNAUTHORIZED_ACCESS", unauthorized_details, client_ip=client_ip, username=username)
                        # IMMEDIATE MITIGATION: Block IP and stop attack immediately
                        if RECOVERY_ENABLED and get_recovery_manager:
                            recovery_manager = get_recovery_manager()
                            recovery_manager.record_attack_start("UNAUTHORIZED_ACCESS", client_ip, unauthorized_details, duration=None)
                            recovery_manager.record_attack_end("UNAUTHORIZED_ACCESS", client_ip)
                            logger.warning(f"🛡️  Unauthorized access attempt from {client_ip} detected and blocked immediately")
                except Exception as e:
                    logger.error(f"Error in unauthorized access detection: {e}")
            
            log_event("LOGIN_FAILED", f"Failed login attempt for {username} (Attempt {login.failed_attempts[client_ip]})", client_ip=client_ip, username=username)
            
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Get username before clearing session (for logging)
    username = session.get('username')
    # Clear session
    session.clear()
    logger.info("User logged out")
    log_event("LOGOUT", "User logged out", username=username)
    # Note: Camera and detection continue running after logout for security monitoring
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/register')
def register():
    # Redirect to the new create-user page with OTP verification
    return redirect(url_for('create_user'))

@app.route('/create-user')
def create_user():
    return render_template('create_user.html')

@app.route('/api/verify-admin-code', methods=['POST'])
def verify_admin_code():
    """Verify admin code for user creation with rate limiting"""
    data = request.get_json()
    code = data.get('code', '')
    client_ip = request.remote_addr
    
    # Check if IP is locked out
    if is_ip_locked_out(client_ip):
        return jsonify({
            "success": False,
            "message": f"Too many attempts. Please try again in {int(LOCKED_OUT_IPS[client_ip] - time.time())} seconds",
            "locked": True
        }), 403
    
    # Initialize attempt counter
    if client_ip not in ADMIN_CODE_ATTEMPTS:
        ADMIN_CODE_ATTEMPTS[client_ip] = 0
    
    # Check admin code
    if code in ADMIN_CODES or code == INITIAL_ADMIN_CODE:
        # Reset attempts on success
        if client_ip in ADMIN_CODE_ATTEMPTS:
            del ADMIN_CODE_ATTEMPTS[client_ip]
        return jsonify({
            "success": True,
            "message": "Admin code verified successfully"
        })
    else:
        # Increment attempt counter
        ADMIN_CODE_ATTEMPTS[client_ip] += 1
        attempts_left = MAX_ADMIN_ATTEMPTS - ADMIN_CODE_ATTEMPTS[client_ip]
        
        if attempts_left <= 0:
            # Lock out the IP
            LOCKED_OUT_IPS[client_ip] = time.time() + LOCKOUT_DURATION
            del ADMIN_CODE_ATTEMPTS[client_ip]
            return jsonify({
                "success": False,
                "message": "Too many attempts. Please try again later.",
                "locked": True
            }), 403
        
        logger.warning(f"Invalid admin code attempt from {client_ip}. {attempts_left} attempts left")
        return jsonify({
            "success": False,
            "message": f"Invalid admin code. {attempts_left} attempts left",
            "attempts_left": attempts_left
        }), 403

@app.route('/api/request-otp', methods=['POST'])
def request_otp():
    """Request OTP for email verification"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    # Basic email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({
            "success": False,
            "message": "Invalid email format"
        }), 400
    
    # Generate and store OTP
    otp = generate_otp()
    OTP_STORAGE[email] = {
        'otp': otp,
        'expiry': time.time() + OTP_EXPIRY,
        'attempts': 0
    }
    
    # Send OTP via email
    if send_otp_email(email, otp):
        return jsonify({
            "success": True,
            "message": "OTP sent to your email"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Failed to send OTP. Please try again."
        }), 500

@app.route('/api/debug/otps', methods=['GET'])
def debug_otps():
    """Debug endpoint to view current OTP storage (for testing only)"""
    return jsonify({
        "otp_storage": OTP_STORAGE,
        "admin_attempts": ADMIN_CODE_ATTEMPTS,
        "locked_ips": LOCKED_OUT_IPS
    })

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP for email"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '')
    
    if not email or not otp:
        return jsonify({
            "success": False,
            "message": "Email and OTP are required"
        }), 400
    
    # Check if OTP exists
    if email not in OTP_STORAGE:
        return jsonify({
            "success": False,
            "message": "OTP expired or not requested"
        }), 400
    
    otp_data = OTP_STORAGE[email]
    
    # Check OTP expiry
    if time.time() > otp_data['expiry']:
        del OTP_STORAGE[email]
        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400
    
    # Check attempts
    if otp_data['attempts'] >= 3:
        del OTP_STORAGE[email]
        return jsonify({
            "success": False,
            "message": "Maximum OTP attempts exceeded"
        }), 400
    
    # Verify OTP
    if otp != otp_data['otp']:
        OTP_STORAGE[email]['attempts'] += 1
        return jsonify({
            "success": False,
            "message": "Invalid OTP",
            "attempts_left": 3 - OTP_STORAGE[email]['attempts']
        }), 400
    
    # OTP verified successfully
    OTP_STORAGE[email]['verified'] = True
    return jsonify({
        "success": True,
        "message": "OTP verified successfully"
    })

@app.route('/api/create-user', methods=['POST'])
def api_create_user():
    """Create new user with OTP verification"""
    data = request.get_json()
    
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '')
    
    # Debug logging
    print(f"\n{'='*50}")
    print(f"USER CREATION ATTEMPT")
    print(f"Username: {username}")
    print(f"Email: {email}")
    print(f"OTP provided: {otp}")
    print(f"Current OTP_STORAGE: {OTP_STORAGE}")
    print(f"{'='*50}\n")
    
    # Input validation
    if not all([username, password, email, otp]):
        print("ERROR: Missing required fields")
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400
    
    # Verify OTP
    if email not in OTP_STORAGE:
        print(f"ERROR: No OTP found for email {email}")
        return jsonify({
            "success": False,
            "message": "OTP expired or not requested"
        }), 400
    
    otp_data = OTP_STORAGE[email]
    
    # Check OTP expiry
    if time.time() > otp_data['expiry']:
        del OTP_STORAGE[email]
        print(f"ERROR: OTP expired for email {email}")
        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400
    
    # Check if OTP has been verified
    if not otp_data.get('verified', False):
        print(f"ERROR: OTP not verified for email {email}")
        return jsonify({
            "success": False,
            "message": "Please verify your OTP first"
        }), 400
    
    # Verify OTP matches (double check)
    if otp != otp_data['otp']:
        print(f"ERROR: OTP mismatch for email {email}")
        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400
    
    # OTP verified, proceed with user creation
    users = load_users()
    
    # Check if username or email already exists
    if username in users:
        return jsonify({
            "success": False,
            "message": "Username already exists"
        }), 400
    
    if any(user_data.get('email') == email for user_data in users.values()):
        return jsonify({
            "success": False,
            "message": "Email already registered"
        }), 400
    
    # Hash password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Create new user
    users[username] = {
        "username": username,
        "password": hashed_password,
        "email": email,
        "role": "user",  # Default role
        "created_at": datetime.now().isoformat()
    }
    
    # Save updated users
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=4)
    
    # Clean up OTP
    if email in OTP_STORAGE:
        del OTP_STORAGE[email]
    
    logger.info(f"New user created: {username}")
    log_event("USER_CREATED", f"New user account created: {username}", session_id=session.get('session_id'), client_ip=request.remote_addr, username=username)
    
    return jsonify({
        "success": True,
        "message": "Administrator created successfully"
    })

@app.route('/api/update-profile', methods=['POST'])
@login_required
def api_update_profile():
    """Update user profile information"""
    data = request.get_json()
    
    username = session.get('username')
    new_email = data.get('email', '').strip()
    otp = data.get('otp', '').strip()
    
    if not new_email:
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400
    
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', new_email):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address"
        }), 400

    # Require OTP verification for new email
    otp_entry = OTP_STORAGE.get(new_email)
    now = time.time()
    if not otp or not otp_entry:
        return jsonify({
            "success": False,
            "message": "OTP verification required for email update"
        }), 400
    if now > otp_entry.get('expiry', 0):
        OTP_STORAGE.pop(new_email, None)
        return jsonify({
            "success": False,
            "message": "OTP expired. Please request a new OTP."
        }), 400
    if otp_entry.get('otp') != otp:
        # increment attempts
        attempts = otp_entry.get('attempts', 0) + 1
        otp_entry['attempts'] = attempts
        if attempts >= 3:
            OTP_STORAGE.pop(new_email, None)
            return jsonify({
                "success": False,
                "message": "Maximum OTP attempts exceeded. Please request a new OTP."
            }), 400
        return jsonify({
            "success": False,
            "message": f"Invalid OTP. Attempts left: {3 - attempts}"
        }), 400
    # OTP verified
    OTP_STORAGE.pop(new_email, None)
    
    # Update user email
    if username in USERS:
        USERS[username]['email'] = new_email
        session['email'] = new_email
        
        logger.info(f"Profile updated for user: {username}")
        log_event("PROFILE_UPDATED", f"User {username} updated profile", client_ip=request.remote_addr, username=username)
        
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "email": new_email
        })
    
    return jsonify({
        "success": False,
        "message": "User not found"
    }), 404

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password"""
    data = request.get_json()
    
    username = session.get('username')
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not current_password or not new_password or not confirm_password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400
    
    # Verify current password
    if username in USERS and USERS[username]['password'] != current_password:
        return jsonify({
            "success": False,
            "message": "Current password is incorrect"
        }), 400
    
    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "message": "New passwords do not match"
        }), 400
    
    if len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters long"
        }), 400
    
    # Update password
    USERS[username]['password'] = new_password
    
    logger.info(f"Password changed for user: {username}")
    log_event("PASSWORD_CHANGED", f"User {username} changed password", client_ip=request.remote_addr, username=username)
    
    return jsonify({
        "success": True,
        "message": "Password changed successfully"
    })

@app.route('/api/get-user-profile', methods=['GET'])
def api_get_user_profile():
    """Get current user profile information"""
    username = session.get('username')
    
    if not username:
        return jsonify({
            "success": False,
            "message": "Not logged in"
        }), 401
    
    if username in USERS:
        user_data = USERS[username].copy()
        # Remove password from response
        user_data.pop('password', None)
        
        return jsonify({
            "success": True,
            "user": user_data
        })
    else:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

@app.route('/api/camera/start', methods=['POST'])
@login_required
def api_camera_start():
    """Start camera and recording"""
    try:
        # Check if camera is already connected
        if runtime.get("camera_connected", False) and camera is not None:
            # Test if camera is still working
            try:
                ret, frame = camera.read()
                if ret and frame is not None:
                    return jsonify({
                        "success": True,
                        "message": "Camera is already running",
                        "camera_connected": True
                    })
            except:
                # Camera might be disconnected, try to reinitialize
                pass
        
        # Initialize camera
        if init_camera():
            logger.info(f"Camera started by user: {session.get('username')}")
            start_new_recording()
            log_event("CAMERA_STARTED", f"Camera started by {session.get('username')}", client_ip=request.remote_addr, username=session.get('username'))
            
            return jsonify({
                "success": True,
                "message": "Camera started successfully",
                "camera_connected": True
            })
        else:
            error_msg = "Failed to start camera. Please check:\n1. Camera is connected\n2. No other application is using the camera\n3. Camera drivers are installed"
            logger.error(error_msg)
            return jsonify({
                "success": False,
                "message": error_msg
            }), 500
    except Exception as e:
        logger.error(f"Error starting camera: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": f"Error starting camera: {str(e)}"
        }), 500

@app.route('/api/camera/stop', methods=['POST'])
@login_required
def api_camera_stop():
    """Stop camera and recording"""
    try:
        username = session.get('username')
        logger.info(f"Camera stopped by user: {username}")
        log_event("CAMERA_STOPPED", f"Camera stopped by {username}", client_ip=request.remote_addr, username=username)
        
        # Stop recording and release camera
        stop_recording()
        release_camera()
        
        return jsonify({
            "success": True,
            "message": "Camera stopped successfully",
            "camera_connected": False
        })
    except Exception as e:
        logger.error(f"Error stopping camera: {e}")
        return jsonify({
            "success": False,
            "message": f"Error stopping camera: {str(e)}"
        }), 500

@app.route('/api/camera/status', methods=['GET'])
@login_required
def api_camera_status():
    """Get camera status"""
    return jsonify({
        "success": True,
        "camera_connected": runtime["camera_connected"],
        "recording": recording_enabled and video_writer is not None
    })

@app.route('/api/generate-admin-code', methods=['POST'])
@login_required
def api_generate_admin_code():
    """Generate new admin code (for administrators only)"""
    if session.get('role') != 'Administrator':
        return jsonify({
            "success": False,
            "message": "Unauthorized access"
        }), 403
    
    new_code = generate_admin_code()
    
    logger.info(f"New admin code generated by {session.get('username')}")
    log_event("ADMIN_CODE_GENERATED", f"Admin code generated by {session.get('username')}", client_ip=request.remote_addr, username=session.get('username'))
    
    return jsonify({
        "success": True,
        "code": new_code,
        "message": "New admin code generated"
    })

@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/status', methods=['GET'])
def status():
    # Network Attack Detection for all requests
    client_ip = request.remote_addr
    request_time = time.time()
    
    if ATTACK_DETECTION_ENABLED and get_network_attack_detector:
        try:
            network_detector = get_network_attack_detector()
            
            # Detect DoS Flood (for all requests)
            dos_detected, dos_confidence, dos_details = network_detector.detect_dos_flood(client_ip, request_time)
            if dos_detected and dos_confidence > 0.85:
                log_event("DOS_FLOOD", dos_details, client_ip=client_ip, username=session.get('username') if has_request_context() else None)
                # Record attack for recovery tracking
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    recovery_manager.record_attack_start("DOS_FLOOD", client_ip, dos_details, duration=30)
            
            # Detect Port Scan
            port = request.environ.get('SERVER_PORT', 5000)
            endpoint = request.path
            scan_detected, scan_confidence, scan_details = network_detector.detect_port_scan(client_ip, port, endpoint)
            if scan_detected and scan_confidence > 0.85:
                log_event("PORT_SCAN", scan_details, client_ip=client_ip, username=session.get('username') if has_request_context() else None)
                # Record attack for recovery tracking
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    recovery_manager.record_attack_start("PORT_SCAN", client_ip, scan_details, duration=20)
        except Exception as e:
            logger.error(f"Error in network attack detection: {e}", exc_info=True)
    
    # Load logs from persistent storage for complete history
    try:
        persistent_logs = load_logs_from_file()
        
        # Ensure persistent_logs is a list
        if not isinstance(persistent_logs, list):
            persistent_logs = []
        
        # Merge with in-memory logs (in-memory might have newer entries)
        # Create a set of IDs from persistent logs for fast lookup
        persistent_ids = {log.get("id") for log in persistent_logs if log.get("id")}
        
        # Start with persistent logs
        logs_to_return = persistent_logs.copy()
        
        # Add any new entries from in-memory that aren't in persistent
        if len(detection_log) > 0:
            for mem_entry in detection_log:
                mem_id = mem_entry.get("id")
                if mem_id and mem_id not in persistent_ids:
                    logs_to_return.append(mem_entry)
                    persistent_ids.add(mem_id)
        
        # Sort by timestamp to ensure chronological order (newest last for display)
        logs_to_return.sort(key=lambda x: x.get("timestamp", x.get("time", "")), reverse=False)
        
        # Ensure all entries have required fields
        for log in logs_to_return:
            if 'id' not in log:
                log['id'] = str(uuid.uuid4())
            if 'time' not in log and 'timestamp' in log:
                try:
                    dt = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    log['time'] = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    log['time'] = log.get('timestamp', 'N/A')
            if 'timestamp' not in log and 'time' in log:
                try:
                    dt = datetime.strptime(log['time'], "%Y-%m-%d %H:%M:%S")
                    log['timestamp'] = dt.isoformat()
                except:
                    log['timestamp'] = log.get('time', '')
            if 'event_type' not in log:
                log['event_type'] = 'INFO'
            if 'reason' not in log:
                log['reason'] = 'No reason provided'
        
    except Exception as e:
        logger.error(f"Error loading logs for status: {e}", exc_info=True)
        logs_to_return = detection_log if detection_log else []
    
    return jsonify({
        "detection_enabled": runtime["detection_enabled"],
        "manual_attack": runtime["manual_attack"],
        "inject_enabled": runtime["inject_enabled"],
        "status": runtime["status"],
        "camera_connected": runtime["camera_connected"],
        "last_alert_time": runtime["last_alert_time"],
        "sound_active": runtime["sound_active"],
        "log": logs_to_return,  # Return all logs from persistent storage
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/control', methods=['POST'])
def control():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    action = data.get('action')
    if not action:
        return jsonify({"error": "No action provided"}), 400
    
    # Detect suspicious control patterns
    client_ip = request.remote_addr
    current_time = datetime.now()
    request_time = time.time()
    
    # Network Attack Detection
    if ATTACK_DETECTION_ENABLED and get_network_attack_detector:
        try:
            network_detector = get_network_attack_detector()
            
            # Detect Port Scan / Reconnaissance (only alert on high confidence)
            port = request.environ.get('SERVER_PORT', 5000)
            endpoint = request.path
            scan_detected, scan_confidence, scan_details = network_detector.detect_port_scan(client_ip, port, endpoint)
            if scan_detected and scan_confidence > 0.85:  # Increased from 0.7 to 0.85
                log_event("PORT_SCAN", scan_details, client_ip=client_ip, username=session.get('username'))
                # Record attack for recovery tracking (estimate 20s duration for port scans)
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    recovery_manager.record_attack_start("PORT_SCAN", client_ip, scan_details, duration=20)
            
            # Detect DoS Flood (only alert on high confidence)
            dos_detected, dos_confidence, dos_details = network_detector.detect_dos_flood(client_ip, request_time)
            if dos_detected and dos_confidence > 0.85:  # Increased from 0.7 to 0.85
                log_event("DOS_FLOOD", dos_details, client_ip=client_ip, username=session.get('username'))
                # Record attack for recovery tracking (estimate 30s duration for DDoS)
                if RECOVERY_ENABLED and get_recovery_manager:
                    recovery_manager = get_recovery_manager()
                    recovery_manager.record_attack_start("DOS_FLOOD", client_ip, dos_details, duration=30)
            
            # Detect Web Exploits (only alert on high confidence)
            payload = str(data) if data else ""
            exploit_detected, exploit_confidence, exploit_details = network_detector.detect_web_exploit(endpoint, payload)
            if exploit_detected and exploit_confidence > 0.85:  # Increased from 0.7 to 0.85
                log_event("WEB_EXPLOIT", exploit_details, client_ip=client_ip, username=session.get('username'))
        except Exception as e:
            logger.error(f"Error in network attack detection: {e}", exc_info=True)
    
    # Check for rapid control requests (potential attack)
    if not hasattr(control, 'last_control_time'):
        control.last_control_time = {}
    if not hasattr(control, 'control_count'):
        control.control_count = {}
    
    key = f"{client_ip}:{action}"
    if key in control.last_control_time:
        time_diff = (current_time - control.last_control_time[key]).total_seconds()
        if time_diff < 1.0:  # Less than 1 second between requests
            logger.warning(f"Rapid control requests detected from {client_ip}: {action}")
            log_event("SUSPICIOUS_ACTIVITY", f"Rapid control requests from {client_ip}", client_ip=client_ip, username=session.get('username'))
    
    control.last_control_time[key] = current_time
    control.control_count[key] = control.control_count.get(key, 0) + 1
    
    # Check for excessive control requests
    if control.control_count[key] > 10:
        logger.warning(f"Excessive control requests from {client_ip}: {control.control_count[key]} requests")
        log_event("BRUTE_FORCE_ATTEMPT", f"Excessive control requests from {client_ip}", client_ip=client_ip, username=session.get('username'))
        # Record attack for recovery tracking (estimate 30s duration for brute force)
        if RECOVERY_ENABLED and get_recovery_manager:
            recovery_manager = get_recovery_manager()
            recovery_manager.record_attack_start("BRUTE_FORCE_ATTEMPT", client_ip, f"Excessive control requests from {client_ip}", duration=30)
    
    if action == 'start':
        runtime["detection_enabled"] = True
        logger.info("Detection enabled via API")
    elif action == 'stop':
        runtime["detection_enabled"] = False
        logger.info("Detection disabled via API")
        log_event("SYSTEM_TAMPERING", f"Detection disabled by {client_ip}", client_ip=client_ip, username=session.get('username'))
    elif action == 'toggle_manual':
        if not runtime["manual_attack"]:
            # Start manual attack
            runtime["manual_attack"] = True
            runtime["manual_attack_username"] = session.get('username')  # Store username who triggered the attack
            logger.info("Manual attack started")
            log_event("MANUAL_ATTACK_TRIGGER", f"Manual attack triggered by {client_ip}", client_ip=client_ip, username=session.get('username'))
        else:
            # Stop manual attack - this will trigger session logging
            runtime["manual_attack"] = False
            logger.info("Manual attack stopped")
    elif action == 'toggle_inject':
        if not runtime["inject_enabled"]:
            # Start inject attack
            runtime["inject_enabled"] = True
            runtime["inject_attack_username"] = session.get('username')  # Store username who triggered the attack
            logger.info("Inject attack started")
            log_event("INJECT_ATTACK_TRIGGER", f"Inject attack triggered by {client_ip}", client_ip=client_ip, username=session.get('username'))
        else:
            # Stop inject attack - this will trigger session logging
            runtime["inject_enabled"] = False
            logger.info("Inject attack stopped")
            # Record attack end for recovery
            if RECOVERY_ENABLED and get_recovery_manager:
                recovery_manager = get_recovery_manager()
                recovery_manager.record_attack_end("VIDEO_INJECTION", client_ip)
    else:
        return jsonify({"error": f"Unknown action: {action}"}), 400
    
    return jsonify({"success": True, "action": action, "runtime": runtime})


@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    global detection_log
    
    # Detect suspicious log clearing
    client_ip = request.remote_addr
    logger.warning(f"Log clearing attempt from {client_ip}")
    log_event("SYSTEM_TAMPERING", f"Log clearing attempt by {client_ip}", client_ip=client_ip, username=session.get('username') if has_request_context() else None)
    
    # Clear both in-memory and persistent logs
    detection_log.clear()
    try:
        save_logs_to_file([])  # Clear persistent storage
    except Exception as e:
        logger.error(f"Error clearing persistent logs: {e}")
    
    logger.info("Logs cleared via API")
    return jsonify({"success": True, "message": "Logs cleared"})

@app.route('/api/config', methods=['GET', 'POST'])
def config():
    """Configuration endpoint for injection detection"""
    client_ip = request.remote_addr
    
    if request.method == 'POST':
        data = request.get_json()
        logger.warning(f"Configuration injection attempt from {client_ip}: {data}")
        log_event("CONFIG_INJECTION", f"Config injection attempt by {client_ip}: {list(data.keys())}", client_ip=client_ip, username=session.get('username'))
        
        # Simulate rejecting malicious config changes
        return jsonify({"success": False, "message": "Configuration rejected"}), 403
    
    # GET request - return limited safe config
    return jsonify({"success": True, "config": {"safe_param": "safe_value"}})

@app.route('/api/file', methods=['GET'])
def file_access():
    """File access endpoint for credential theft detection"""
    client_ip = request.remote_addr
    requested_path = request.args.get('path', '')
    
    # Detect suspicious file access
    suspicious_paths = ['/etc/passwd', '/etc/shadow', '/config/', '/admin/', '/system/']
    
    for suspicious in suspicious_paths:
        if suspicious in requested_path:
            logger.warning(f"Credential theft attempt from {client_ip}: {requested_path}")
            log_event("CREDENTIAL_THEFT", f"File access attempt by {client_ip}: {requested_path}", client_ip=client_ip, username=session.get('username'))
            return jsonify({"error": "Access denied"}), 403
    
    logger.info(f"File access from {client_ip}: {requested_path}")
    return jsonify({"error": "File not found"}), 404

@app.route('/api/exploit', methods=['POST'])
def exploit():
    """Exploit attempt detection"""
    client_ip = request.remote_addr
    data = request.get_json()
    
    logger.error(f"Exploit attempt from {client_ip}: {data}")
    log_event("EXPLOIT_ATTEMPT", f"Exploit attempt by {client_ip}: {data.get('exploit', 'unknown')}", client_ip=client_ip, username=session.get('username'))
    
    return jsonify({"error": "Access denied"}), 403

@app.route('/api/version', methods=['GET'])
def version():
    """Version information disclosure detection"""
    client_ip = request.remote_addr
    
    logger.info(f"Version information requested by {client_ip}")
    log_event("RECONNAISSANCE", f"Version enumeration by {client_ip}", client_ip=client_ip, username=session.get('username'))
    
    return jsonify({"version": "AI-IDS v1.0", "build": "secure"})

@app.route('/api/system', methods=['GET'])
def system_info():
    """System information disclosure detection"""
    client_ip = request.remote_addr
    
    logger.info(f"System information requested by {client_ip}")
    log_event("RECONNAISSANCE", f"System enumeration by {client_ip}", client_ip=client_ip, username=session.get('username'))
    
    return jsonify({"system": "Secure", "status": "Protected"})

@app.route('/api/recordings', methods=['GET'])
def list_recordings():
    """List all recorded video files with filtering and sorting"""
    try:
        # Get query parameters
        sort_by = request.args.get('sort', 'date')  # date, name, size
        order = request.args.get('order', 'desc')    # asc, desc
        date_filter = request.args.get('date', '')   # YYYY-MM-DD or empty for all
        
        recordings = []
        recordings_dir = Config.RECORDINGS_DIR
        
        # Check if recordings directory exists
        if not os.path.exists(recordings_dir):
            os.makedirs(recordings_dir, exist_ok=True)
            return jsonify({
                "recordings": [],
                "available_dates": [],
                "statistics": {
                    "total_count": 0,
                    "total_size": 0,
                    "total_size_mb": 0,
                    "total_size_gb": 0
                }
            })
        
        # Get all video files
        try:
            files = os.listdir(recordings_dir)
        except Exception as e:
            logger.error(f"Error reading recordings directory: {e}")
            return jsonify({
                "recordings": [],
                "available_dates": [],
                "statistics": {
                    "total_count": 0,
                    "total_size": 0,
                    "total_size_mb": 0,
                    "total_size_gb": 0
                }
            }), 500
        
        for filename in files:
            if filename.endswith('.mp4'):
                filepath = os.path.join(recordings_dir, filename)
                stat = os.stat(filepath)
                created_time = datetime.fromtimestamp(stat.st_ctime)
                created_date = created_time.strftime('%Y-%m-%d')
                
                recording = {
                    'filename': filename,
                    'size': stat.st_size,
                    'size_mb': round(stat.st_size / (1024 * 1024), 2),
                    'created': created_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'created_date': created_date,
                    'created_timestamp': int(stat.st_ctime),
                    'download_url': f'/api/download/{filename}',
                    'duration': '5:00'  # Fixed 5-minute duration
                }
                
                # Apply date filter if specified
                if not date_filter or created_date == date_filter:
                    recordings.append(recording)
        
        # Sort recordings
        if sort_by == 'date':
            recordings.sort(key=lambda x: x['created_timestamp'], reverse=(order == 'desc'))
        elif sort_by == 'name':
            recordings.sort(key=lambda x: x['filename'], reverse=(order == 'desc'))
        elif sort_by == 'size':
            recordings.sort(key=lambda x: x['size'], reverse=(order == 'desc'))
        
        # Get available dates for filter dropdown
        available_dates = sorted(set(r['created_date'] for r in recordings), reverse=True)
        
        # Calculate statistics
        total_size = sum(r['size'] for r in recordings)
        total_count = len(recordings)
        
        return jsonify({
            "recordings": recordings,
            "available_dates": available_dates,
            "statistics": {
                "total_count": total_count,
                "total_size": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "total_size_gb": round(total_size / (1024 * 1024 * 1024), 2)
            }
        })
    except Exception as e:
        logger.error(f"Error listing recordings: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/download/<filename>', methods=['GET'])
def download_recording(filename):
    """Download a recorded video file"""
    try:
        recordings_dir = Config.RECORDINGS_DIR
        return send_from_directory(recordings_dir, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading recording: {e}")
        return jsonify({"error": "File not found"}), 404

# Helper functions
def _add_annotation(frame, text, position, color):
    """Add text annotation to frame."""
    return cv2.putText(
        frame.copy(), text, position,
        cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2, cv2.LINE_AA
    )

def _make_placeholder(msg="NO CAMERA"):
    """Create a placeholder image when camera is not available."""
    img = np.zeros((360, 640, 3), dtype=np.uint8)
    img = _add_annotation(img, msg, (20, 180), (0, 0, 255))
    ret, buf = cv2.imencode('.jpg', img)
    return buf.tobytes() if ret else b''

# Detection functions

def detect_obstruction(frame):
    """Detect camera obstruction (lens covered by hand or any object)"""
    current_time = time.time()
    
    # Calculate average brightness
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    avg_brightness = cv2.mean(gray)[0]
    
    # Calculate standard deviation to detect uniform color
    mean, std_dev = cv2.meanStdDev(gray)
    std_dev_value = std_dev[0][0]
    
    is_obstructed = False
    reason = None
    
    # Check if too dark (obstructed by hand or object)
    if avg_brightness < Config.BRIGHTNESS_LOW:
        is_obstructed = True
        reason = f"Camera obstructed (brightness: {avg_brightness:.1f})"
    # Check for uniform color (lens covered by hand/paper/object)
    elif std_dev_value < 15:  # Very low standard deviation means uniform color
        is_obstructed = True
        reason = f"Camera covered (low variance: {std_dev_value:.1f})"
    # Additional check: if brightness drops suddenly compared to normal
    elif avg_brightness < 50:  # Moderately dark but might be covered
        is_obstructed = True
        reason = f"Camera partially covered (brightness: {avg_brightness:.1f})"
    
    return is_obstructed, reason

def handle_obstruction_timing(is_obstructed, reason, frame, current_time):
    """Handle the timing logic for obstruction alerts with grouped notifications"""
    if is_obstructed:
        if runtime["obstruction_start_time"] is None:
            # First detection of obstruction - start new session
            runtime["obstruction_start_time"] = current_time
            runtime["obstruction_notified"] = False
            runtime["sound_alert_played"] = False
            runtime["sound_active"] = False
            runtime["obstruction_session_id"] = datetime.now().strftime("%Y%m%d_%H%M%S")
            runtime["session_logged"] = False
            logger.info("Camera obstruction detected - starting timer")
            # Log obstruction detection (no email yet - email will be sent at 15 seconds)
            # Use a non-important event type to avoid immediate email
            log_event("OBSTRUCTION_STARTED", f"Camera obstruction detected: {reason}", username=None)
        else:
            obstruction_duration = current_time - runtime["obstruction_start_time"]
            
            # 5-second sound alert (beep sound)
            if obstruction_duration >= 5 and not runtime["sound_alert_played"]:
                logger.warning("🔊 Camera covered for 5 seconds - PLAYING BEEP SOUND")
                runtime["sound_alert_played"] = True
                runtime["sound_active"] = True
                # Log sound alert
                log_event("SOUND_ALERT", f"Beep sound played - camera covered for {obstruction_duration:.0f} seconds", username=None)
            
            # 15-second email notification
            if obstruction_duration >= 15 and not runtime["obstruction_notified"]:
                logger.error("🚨 CAMERA COVERED FOR 15 SECONDS - SENDING EMAIL NOTIFICATION 🚨")
                runtime["obstruction_notified"] = True
                
                # Always show console notification
                print("\n" + "="*60)
                print("🚨 CAMERA OBSTRUCTION ALERT 🚨")
                print(f"Camera has been covered for {obstruction_duration:.0f} seconds")
                print(f"Reason: {reason}")
                print("="*60 + "\n")
                
                # Send email notification
                log_event("OBSTRUCTION_DETECTED", f"Camera obstruction alert - covered for {obstruction_duration:.0f} seconds: {reason}", username=None)
                send_notification_email(reason, obstruction_duration, username=None)
        
        return True
    else:
        # Reset obstruction timer if camera is no longer obstructed
        if runtime["obstruction_start_time"] is not None:
            obstruction_duration = current_time - runtime["obstruction_start_time"]
            
            # Create summary log entry for the entire obstruction session (only once)
            if obstruction_duration > 1 and not runtime["session_logged"]:  # Only log if obstruction lasted more than 1 second and not already logged
                session_id = runtime.get("obstruction_session_id", datetime.now().strftime("%Y%m%d_%H%M%S"))
                start_time = datetime.fromtimestamp(runtime["obstruction_start_time"]).strftime("%H:%M:%S")
                end_time = datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
                
                # Create session summary
                summary_data = {
                    "session_id": session_id,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": obstruction_duration,
                    "reason": reason,
                    "sound_alert": runtime["sound_alert_played"],
                    "notification_sent": runtime["obstruction_notified"]
                }
                
                log_event("OBSTRUCTION_SESSION", f"Camera obstruction: {start_time} - {end_time} ({obstruction_duration:.1f}s)", session_data=summary_data, username=None)
                runtime["session_logged"] = True  # Mark as logged to prevent duplicates
            
            # Reset all obstruction tracking variables
            runtime["obstruction_start_time"] = None
            runtime["obstruction_notified"] = False
            runtime["sound_alert_played"] = False
            runtime["sound_active"] = False
            runtime["obstruction_session_id"] = None
            runtime["session_logged"] = False
        
        return False

def handle_manual_attack_timing(is_manual_attack, current_time):
    """Handle the timing logic for manual attack alerts with grouped notifications"""
    if is_manual_attack:
        if runtime["manual_attack_start_time"] is None:
            # First detection of manual attack - start new session
            runtime["manual_attack_start_time"] = current_time
            runtime["manual_attack_session_id"] = datetime.now().strftime("%Y%m%d_%H%M%S")
            runtime["manual_attack_logged"] = False
            logger.info("Manual attack detected - starting session")
        return True
    else:
        # Reset manual attack timer if attack is no longer active
        if runtime["manual_attack_start_time"] is not None:
            attack_duration = current_time - runtime["manual_attack_start_time"]
            
            # Create summary log entry for the entire manual attack session (only once)
            if attack_duration > 1 and not runtime["manual_attack_logged"]:  # Only log if attack lasted more than 1 second and not already logged
                session_id = runtime.get("manual_attack_session_id", datetime.now().strftime("%Y%m%d_%H%M%S"))
                start_time = datetime.fromtimestamp(runtime["manual_attack_start_time"]).strftime("%H:%M:%S")
                end_time = datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
                
                # Create session summary
                summary_data = {
                    "session_id": session_id,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": attack_duration,
                    "attack_type": "Manual",
                    "reason": "Manual attack triggered"
                }
                
                # Use stored username for notification
                manual_username = runtime.get("manual_attack_username")
                log_event("MANUAL_ATTACK_SESSION", f"Manual attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data, username=manual_username)
                runtime["manual_attack_logged"] = True  # Mark as logged to prevent duplicates
            
            # Reset all manual attack tracking variables
            runtime["manual_attack_start_time"] = None
            runtime["manual_attack_session_id"] = None
            runtime["manual_attack_logged"] = False
            runtime["manual_attack_username"] = None
        
        return False

def handle_inject_attack_timing(is_inject_attack, current_time):
    """Handle the timing logic for inject attack alerts with grouped notifications"""
    if is_inject_attack:
        if runtime["inject_attack_start_time"] is None:
            # First detection of inject attack - start new session
            runtime["inject_attack_start_time"] = current_time
            runtime["inject_attack_session_id"] = datetime.now().strftime("%Y%m%d_%H%M%S")
            runtime["inject_attack_logged"] = False
            logger.info("Inject attack detected - starting session")
            # Log the trigger only once when attack starts (if username is available)
            if runtime.get("inject_attack_username"):
                log_event("INJECT_ATTACK_TRIGGER", f"Inject attack started", username=runtime["inject_attack_username"])
        return True
    else:
        # Reset inject attack timer if attack is no longer active
        if runtime["inject_attack_start_time"] is not None:
            attack_duration = current_time - runtime["inject_attack_start_time"]
            
            # Create summary log entry for the entire inject attack session (only once)
            if attack_duration > 1 and not runtime["inject_attack_logged"]:  # Only log if attack lasted more than 1 second and not already logged
                session_id = runtime.get("inject_attack_session_id", datetime.now().strftime("%Y%m%d_%H%M%S"))
                start_time = datetime.fromtimestamp(runtime["inject_attack_start_time"]).strftime("%H:%M:%S")
                end_time = datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
                
                # Create session summary
                summary_data = {
                    "session_id": session_id,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": attack_duration,
                    "attack_type": "Inject",
                    "reason": "Video injection attack detected"
                }
                
                # Use stored username for notification
                inject_username = runtime.get("inject_attack_username")
                log_event("INJECT_ATTACK_SESSION", f"Inject attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data, username=inject_username)
                runtime["inject_attack_logged"] = True  # Mark as logged to prevent duplicates
            
            # Reset all inject attack tracking variables
            runtime["inject_attack_start_time"] = None
            runtime["inject_attack_session_id"] = None
            runtime["inject_attack_logged"] = False
            runtime["inject_attack_username"] = None
        
        return False

def send_notification_email(reason, duration, username=None):
    """Send email notification about security events"""
    import smtplib
    import socket
    from email.mime.text import MIMEText
    
    try:
        logger.info("Starting email notification process...")
        
        # Check if email is configured (loaded from .env file)
        logger.info(f"Using email: {Config.MAIL_USERNAME}")
        
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            error_msg = "Email credentials not configured - notification not sent"
            logger.warning(error_msg)
            return False
            
        # Determine recipient email based on provided username or session
        recipient_email = None
        if username:
            users = load_users()
            user_data = users.get(username)
            if user_data and user_data.get('email'):
                recipient_email = user_data['email']
        elif has_request_context() and 'username' in session: # Fallback to session if available
            try:
                current_session_username = session.get('username')
                users = load_users()
                user_data = users.get(current_session_username)
                if user_data and user_data.get('email'):
                    recipient_email = user_data['email']
            except RuntimeError:
                # Session not available in this context
                pass

        # If no specific user email found, try to send to admins or any user with email from users.json
        if not recipient_email:
            users = load_users()
            # Find first admin user with email
            for user_name, user_data in users.items():
                user_role = user_data.get('role', '').lower()
                if (user_role == 'administrator' or user_role == 'admin') and user_data.get('email'):
                    recipient_email = user_data['email']
                    logger.info(f"No specific user email found, sending obstruction notification to admin: {user_name}")
                    break
            # If still no admin found, try any user with email
            if not recipient_email:
                for user_name, user_data in users.items():
                    if user_data.get('email'):
                        recipient_email = user_data['email']
                        logger.info(f"No admin email found, sending obstruction notification to user: {user_name}")
                        break
        
        if not recipient_email:
            error_msg = "No recipient email found in users.json - notification not sent"
            logger.warning(error_msg)
            return False

        # Prepare email notification
        subject = f"[AI-IDS] Security Alert - {reason}"
        body = f"""
        Security Alert!

        Type: {reason}
        Duration: {duration:.0f} seconds
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        Please check the system immediately.

        --
        AI Intrusion Detection System
        """

        # Create message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = Config.MAIL_USERNAME
        msg['To'] = recipient_email

        # Send email using Gmail SMTP with detailed logging
        logger.info(f"Attempting to connect to {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
        
        try:
            # Create connection with timeout
            server = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10)
            logger.info("SMTP connection established")
            
            # Start TLS
            logger.info("Starting TLS...")
            server.ehlo()
            server.starttls()
            server.ehlo()
            
            # Login
            logger.info("Attempting to login...")
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            logger.info("Login successful")
            
            # Send email
            logger.info(f"Sending email to {recipient_email}...")
            server.send_message(msg)
            logger.info(f"✓ Email notification sent successfully to {recipient_email}")
            
            # Quit server
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f"SMTP Authentication Error: {str(e)}. Please check your email and app password."
            logger.error(error_msg)
        except smtplib.SMTPException as e:
            error_msg = f"SMTP Error: {str(e)}"
            logger.error(error_msg)
        except socket.timeout as e:
            error_msg = f"Connection timeout: {str(e)}. Check your internet connection and firewall settings."
            logger.error(error_msg)
        except socket.gaierror as e:
            error_msg = f"Address-related error: {str(e)}. Check your SMTP server and port."
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
        return False
        
    except Exception as e:
        error_msg = f"Fatal error in send_notification_email: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return False

# Detection loop that runs continuously in background (works even after logout)
def run_detection_loop():
    """Continuous detection loop - runs independently of video feed requests"""
    # Initialize recovery manager if available
    recovery_manager = None
    if RECOVERY_ENABLED and get_recovery_manager:
        recovery_manager = get_recovery_manager()
        logger.info("Recovery manager initialized in detection loop")
    
    global current_frame, runtime, video_writer, video_start_time
    prev_frame = None
    obstruction_count = 0
    frame_counter = 0
    
    # Start recording when camera initializes
    if recording_enabled and video_writer is None and runtime["camera_connected"]:
        start_new_recording()
    
    while True:
        # Auto-initialize camera if not connected (works even after logout)
        if not runtime["camera_connected"]:
            if not init_camera():
                time.sleep(2)
                continue
            
            # Start recording when camera connects
            if recording_enabled and video_writer is None:
                start_new_recording()
        
        # Ensure detection is enabled by default for security (works even after logout)
        if not runtime.get("detection_enabled", False):
            runtime["detection_enabled"] = True
            logger.info("Detection auto-enabled for security monitoring")

        try:
            success, frame = camera.read()
            if not success or frame is None:
                logger.warning("Failed to read frame from camera, attempting to re-initialize.")
                # Detect cable cutting / camera disconnect
                if runtime["camera_connected"]:
                    log_event("CABLE_CUTTING", "Camera disconnected - possible cable cutting or tampering", username=None)
                release_camera() # Release existing camera
                time.sleep(1) # Wait a bit before trying to re-initialize
                runtime["camera_connected"] = False # Mark as disconnected to trigger re-init
                continue

            is_alert = False
            alert_reason = None
            annotated_frame = frame.copy()
            
            # Resize frame for consistent recording (use INTER_LINEAR for speed)
            frame = cv2.resize(frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT), interpolation=cv2.INTER_LINEAR)
            annotated_frame = cv2.resize(annotated_frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT), interpolation=cv2.INTER_LINEAR)
            
            # Add timestamp to all frames for CCTV recording
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            annotated_frame = _add_annotation(annotated_frame, timestamp, (10, Config.FRAME_HEIGHT - 20), (255, 255, 255))
            
            # Process frame based on current state
            if runtime["inject_enabled"]:
                # Simulate video freeze/injection
                annotated_frame = _add_annotation(frame, "INJECT: FREEZE", (10, 50), (0, 165, 255))
                is_alert = True
                # Don't set alert_reason here - let handle_inject_attack_timing handle logging
                # This prevents repeated logging every frame
                alert_reason = None  # Will be set by handle_inject_attack_timing if needed
            elif not runtime["detection_enabled"]:
                annotated_frame = _add_annotation(frame, "Status: Detection OFF", (10, 30), (0, 255, 0))
            else:
                # Manual attack simulation with session handling
                if runtime["manual_attack"]:
                    is_alert = True
                    alert_reason = "Manual attack triggered"
                    # Don't reset immediately - let session timing handle it
                    # The session will end when manual_attack is set to False by control endpoint
                    
                # Obstruction detection with timing
                obstruction_detected, obstruction_msg = detect_obstruction(frame)
                handle_obstruction_timing(obstruction_detected, obstruction_msg, frame, time.time())
                
                if obstruction_detected:
                    is_alert = True
                    alert_reason = obstruction_msg
                
                # Comprehensive Attack Detection (run less frequently for performance)
                if ATTACK_DETECTION_ENABLED and get_attack_detector and frame_counter % 10 == 0:  # Run every 10th frame
                    try:
                        attack_detector = get_attack_detector()
                        current_timestamp = time.time()
                        
                        # 1. Frame Freeze Detection (only alert on high confidence)
                        freeze_detected, freeze_confidence, freeze_details = attack_detector.detect_frame_freeze(frame)
                        if freeze_detected and freeze_confidence > 0.85:  # Increased from 0.7 to 0.85
                            is_alert = True
                            if alert_reason:
                                alert_reason = f"{alert_reason} | Frame Freeze: {freeze_details}"
                            else:
                                alert_reason = f"Frame Freeze: {freeze_details}"
                            log_event("FRAME_FREEZE", freeze_details, username=None)
                        
                        # 2. Video Injection Detection (only alert on high confidence, only once - not in loop)
                        injection_detected, injection_confidence, injection_details = attack_detector.detect_video_injection(frame, current_timestamp)
                        if injection_detected and injection_confidence > 0.85:  # Increased from 0.8 to 0.85 to reduce false positives
                            # Only log and record once, not repeatedly in loop
                            if not runtime.get("video_injection_detected", False):
                                is_alert = True
                                if alert_reason:
                                    alert_reason = f"{alert_reason} | Video Injection: {injection_details}"
                                else:
                                    alert_reason = f"Video Injection: {injection_details}"
                                log_event("VIDEO_INJECTION", injection_details, username=None)
                                runtime["video_injection_detected"] = True
                                runtime["video_injection_last_logged"] = current_timestamp
                                # Record attack for recovery tracking (only once)
                                if RECOVERY_ENABLED and get_recovery_manager:
                                    recovery_manager = get_recovery_manager()
                                    recovery_manager.record_attack_start("VIDEO_INJECTION", None, injection_details)
                            else:
                                # Already detected, just show alert but don't log again
                                is_alert = True
                                if not alert_reason:
                                    alert_reason = "Video Injection: Ongoing"
                        else:
                            # Reset detection flag if injection is no longer detected (after 5 seconds)
                            if runtime.get("video_injection_detected", False):
                                last_logged = runtime.get("video_injection_last_logged")
                                if last_logged and (current_timestamp - last_logged > 5):
                                    runtime["video_injection_detected"] = False
                                    runtime["video_injection_last_logged"] = None
                        
                        # 3. Motion Masking Detection (only alert on high confidence)
                        if prev_frame is not None:
                            masking_detected, masking_confidence, masking_details = attack_detector.detect_motion_masking(frame, prev_frame)
                            if masking_detected and masking_confidence > 0.75:  # Increased from 0.6 to 0.75
                                is_alert = True
                                if alert_reason:
                                    alert_reason = f"{alert_reason} | Motion Masking: {masking_details}"
                                else:
                                    alert_reason = f"Motion Masking: {masking_details}"
                                log_event("MOTION_MASKING", masking_details, username=None)
                    except Exception as e:
                        logger.error(f"Error in attack detection: {e}", exc_info=True)
                
                # Add status text
                status_text = "Status: Monitoring"
                status_color = (0, 255, 0)
                
                if is_alert:
                    annotated_frame = _add_annotation(annotated_frame, f"ALERT: {alert_reason}", (10, 30), (0, 0, 255))
                    runtime["status"] = "ALERT"
                else:
                    annotated_frame = _add_annotation(annotated_frame, status_text, (10, 30), status_color)
                    runtime["status"] = "Running"

            # Handle attack session timing
            current_time = time.time()
            
            # Update manual attack timing based on runtime flag
            handle_manual_attack_timing(runtime["manual_attack"], current_time)
            
            # Update inject attack timing based on runtime flag
            handle_inject_attack_timing(runtime["inject_enabled"], current_time)
            
            # Only log generic ALERTs if they are not part of an ongoing session
            if is_alert and alert_reason:
                should_log_alert = True

                # Check if an obstruction session is active and handling this alert
                if runtime["obstruction_start_time"] and ("obstructed" in alert_reason or "covered" in alert_reason):
                    should_log_alert = False
                # Check if a manual attack session is active and handling this alert
                elif runtime["manual_attack_start_time"] and alert_reason == "Manual attack triggered":
                    should_log_alert = False
                # Check if an inject attack session is active - don't log generic alerts during inject
                elif runtime["inject_attack_start_time"]:
                    should_log_alert = False

                if should_log_alert:
                    log_event("ALERT", alert_reason)
            
            # Write frame to video file (CCTV recording) - skip some frames for performance
            if frame_counter % 2 == 0:  # Write every other frame to video
                write_frame_to_video(annotated_frame)
            
            # Store previous frame for motion detection (only if needed)
            if prev_frame is None or frame_counter % 3 == 0:  # Update every 3rd frame
                prev_frame = frame.copy()

            # Encode the frame for web streaming (optimize JPEG quality for speed)
            encode_params = [cv2.IMWRITE_JPEG_QUALITY, 70]  # Reduced quality for faster encoding
            ret, buffer = cv2.imencode('.jpg', annotated_frame, encode_params)
            if not ret:
                logger.warning("Failed to encode frame")
                continue

            frame_bytes = buffer.tobytes()
            with frame_lock:
                current_frame = frame_bytes
            
            frame_counter += 1
            
            # Check and perform recovery (every 1 second for faster response)
            if recovery_manager and frame_counter % 100 == 0:  # Check every ~1 second at 100 FPS
                try:
                    recovered = recovery_manager.check_and_recover()
                    for attack_type, attack_id in recovered:
                        recovery_msg = f"System recovered from {attack_type} attack"
                        log_event("RECOVERY_COMPLETE", recovery_msg, username=None)
                        logger.info(f"✅ {recovery_msg}")
                except Exception as e:
                    logger.error(f"Error in recovery check: {e}", exc_info=True)
            
            # Minimal sleep for faster frame rate (target ~60 FPS)
            time.sleep(0.01)  # ~10ms = ~100 FPS max (but camera limits actual rate)
                
        except Exception as e:
            logger.error(f"Error in detection loop: {e}")
            time.sleep(1)
            continue

# Frame generation and processing (for video feed streaming)
def gen_frames():
    """Generate frames for video feed - uses latest frame from detection loop"""
    global current_frame
    while True:
        try:
            with frame_lock:
                if current_frame is not None:
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + current_frame + b'\r\n')
                else:
                    # If no frame available yet, wait a bit
                    time.sleep(0.1)
                    continue
        except Exception as e:
            logger.error(f"Error in frame generation: {str(e)}")
            time.sleep(1)

# Cleanup on exit
import atexit
@atexit.register
def cleanup():
    release_camera()
    logger.info("Application shutting down")

# Add a simple test route at the end of the file

@app.route('/test-email', methods=['GET'])
@app.route('/api/test-email', methods=['GET'])  # Alternative endpoint
def test_email_route():
    """Test email sending functionality"""
    try:
        # Test email configuration
        logger.info("\n=== Starting Email Test ===")
        logger.info(f"Sender email: {Config.MAIL_USERNAME}")
        logger.info(f"SMTP Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
        logger.info(f"Using TLS: {Config.MAIL_USE_TLS}")
        
        # Verify email configuration
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            error_msg = "Email username or password not configured"
            logger.error(error_msg)
            return error_msg
        
        # Get recipient email from current user or first available user
        recipient_email = get_alert_email()
        if not recipient_email:
            error_msg = "No user email found - cannot send test email. Please ensure at least one user has an email configured."
            logger.error(error_msg)
            return error_msg
        
        logger.info(f"Recipient email: {recipient_email}")
        
        logger.info("Configuration check passed. Attempting to send test email...")
        
        # Test sending email with more context
        start_time = time.time()
        success = send_notification_email("Test Alert - AI-IDS System", 5)
        elapsed = time.time() - start_time
        
        if success:
            logger.info(f"Test email sent successfully in {elapsed:.2f} seconds!")
            return "Test email sent successfully! Please check your inbox (and spam folder)."
        else:
            error_msg = "Failed to send test email - check server logs for details"
            logger.error(error_msg)
            return error_msg
            
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP Authentication Error: {str(e)}\nPlease check your email and app password."
        logger.error(error_msg, exc_info=True)
        return error_msg
    except smtplib.SMTPException as e:
        error_msg = f"SMTP Error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg
    except socket.timeout as e:
        error_msg = f"Connection timeout: {str(e)}\nCheck your internet connection and firewall settings."
        logger.error(error_msg, exc_info=True)
        return error_msg
    except socket.gaierror as e:
        error_msg = f"Address-related error: {str(e)}\nCheck your SMTP server and port settings."
        logger.error(error_msg, exc_info=True)
        return error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg

@app.route('/test-email-alert')
def test_email_alert():
    """Test endpoint to trigger an email alert"""
    try:
        # Log a test event which will trigger email notification
        log_event(
            event_type="TEST_ALERT",
            reason="This is a test alert to verify email notifications are working.",
            session_data={"test": True, "timestamp": datetime.now().isoformat()}
        )
        
        return jsonify({
            "status": "success",
            "message": "Test alert triggered. Please check your email."
        }), 200
        
    except Exception as e:
        logger.error(f"Error in test_email_alert: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to send test alert: {str(e)}"
        }), 500

def start_detection_background():
    """Start detection in background thread - runs continuously even after logout"""
    def detection_loop():
        logger.info("Starting background detection loop...")
        try:
            run_detection_loop()
        except Exception as e:
            logger.error(f"Error in background detection loop: {e}")
            # Restart the loop after a delay
            time.sleep(5)
            start_detection_background()
    
    detection_thread = threading.Thread(target=detection_loop, daemon=True)
    detection_thread.start()
    logger.info("Background detection thread started - attack detection will work even after logout")

if __name__ == '__main__':
    # Initialize AI-IDS system (camera will be started automatically)
    logger.info("Initializing AI-IDS system...")
    logger.info("Starting continuous detection monitoring (works even after logout)")
    
    
    # Verify email configuration
    logger.info("\n=== Email Configuration Check ===")
    if Config.MAIL_USERNAME and Config.MAIL_PASSWORD:
        logger.info(f"✓ Gmail Email: {Config.MAIL_USERNAME}")
        logger.info(f"✓ App Password: {'*' * len(Config.MAIL_PASSWORD)} (configured)")
        logger.info(f"✓ SMTP Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
    else:
        logger.warning("⚠ Email not configured!")
        logger.warning("Please create a .env file with:")
        logger.warning("  GMAIL_EMAIL=your-email@gmail.com")
        logger.warning("  GMAIL_APP_PASSWORD=your-16-char-app-password")
        logger.warning("Email notifications will not work until configured.")
    logger.info("=" * 40 + "\n")
    
    # Check Network IDS status and attempt to load pre-trained model
    if NETWORK_IDS_ENABLED and get_network_ids:
        try:
            network_ids = get_network_ids()
            # Try to load pre-trained model if available
            model_paths = [
                'models/network_ids/random_forest_model.pkl',
                'models/network_ids/dnn_model.h5',
                'models/random_forest_model.pkl',
                'models/dnn_model.h5'
            ]
            for model_path in model_paths:
                if os.path.exists(model_path):
                    try:
                        network_ids.load_model(model_path)
                        logger.info(f"✓ AI Network IDS model loaded: {model_path}")
                        logger.info(f"  Model Type: {network_ids.model_type}")
                        logger.info(f"  Accuracy: {network_ids.metrics.get('accuracy', 0):.2%}")
                        break
                    except Exception as e:
                        logger.debug(f"Could not load model {model_path}: {e}")
                        continue
            if not network_ids.is_trained:
                logger.info("ℹ️  Network IDS available but no trained model loaded.")
                logger.info("   Train a model via /api/network-ids/train or load via /api/network-ids/load-model")
                logger.info("   AI network traffic analysis will be disabled until model is trained.")
        except Exception as e:
            logger.warning(f"Error initializing Network IDS: {e}")
    else:
        logger.info("ℹ️  Network IDS not available - AI network traffic analysis disabled")
    
    # Start detection in background thread so it runs continuously
    start_detection_background()
    
    # Debug: List all registered routes
    logger.info("Registered routes:")
    for rule in app.url_map.iter_rules():
        logger.info(f"{rule.endpoint}: {rule.rule}")
    
    # Start the Flask development server
    try:
        logger.info("Starting Flask server...")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        raise
