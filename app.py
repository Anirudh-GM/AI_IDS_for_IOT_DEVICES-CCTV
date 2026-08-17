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
import atexit
from dotenv import load_dotenv

load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

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
    FPS = 20
    OBSTRUCTION_THRESHOLD = 0.85
    MOTION_THRESHOLD = 0.3
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('GMAIL_EMAIL')
    MAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')
    ALERT_EMAIL = ''    # Default recipient email
    
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

def get_alert_email(username=None):
    """
    Get the email address used for security alerts.

    This function does NOT depend on Flask session,
    so alerts can be sent even when nobody is logged in.
    """

    users = load_users()

    # If a username was explicitly supplied, try that user first
    if username and username in users:
        email = users[username].get('email')
        if email:
            return email

    # Prefer an admin user's email
    for user_name, user_data in users.items():
        if user_data.get('role') == 'admin' and user_data.get('email'):
            return user_data['email']

    # Otherwise use the first registered user with an email
    for user_name, user_data in users.items():
        if user_data.get('email'):
            return user_data['email']

    # Optional configured fallback
    return Config.ALERT_EMAIL or None

def start_alert(alert_type, reason, session_data=None, username=None):
    """Start an alert incident and send one email for that active alert type.

    An alert type can have only one active email notification at a time.
    The alert becomes eligible for another email only after resolve_alert()
    removes it from active_alerts.
    """
    global active_alerts

    # Prevent duplicate notifications while this alert type is active.
    with alert_lock:
        if alert_type in active_alerts and active_alerts[alert_type].get("active"):
            logger.info(
                f"Alert already active: {alert_type}. Email will not be sent again."
            )
            return False

        # Reserve the alert type while the SMTP operation is in progress.
        # If sending fails, the reservation is removed so a later occurrence
        # can retry the notification.
        alert_id = str(uuid.uuid4())
        active_alerts[alert_type] = {
            "active": True,
            "alert_id": alert_id,
            "started_at": datetime.now().isoformat(),
            "reason": reason,
            "email_status": "sending"
        }

    recipient_email = None
    try:
        recipient_email = get_alert_email(username=username)

        if not recipient_email:
            logger.warning(
                f"No recipient email available for alert: {alert_type}"
            )
            with alert_lock:
                active_alerts.pop(alert_type, None)
            return False

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        body = f"""AI-IDS SECURITY ALERT

Alert Type:
{alert_type}

Reason:
{reason}

Time:
{timestamp}

Alert ID:
{alert_id}

Status:
ACTIVE

The system will not send another email for this alert type
while the alert remains active.

A new email will be sent after this alert is resolved and
the same alert type occurs again.

AI-IDS Security System
"""

        if session_data:
            body += "\nSession Data:\n" + json.dumps(session_data, indent=2, default=str) + "\n"

        msg = MIMEText(body)
        msg['Subject'] = f"[AI-IDS] Security Alert - {alert_type}"
        msg['From'] = Config.MAIL_USERNAME
        msg['To'] = recipient_email

        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            raise RuntimeError("Gmail credentials are not configured")

        with smtplib.SMTP(
            Config.MAIL_SERVER,
            Config.MAIL_PORT,
            timeout=10
        ) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)

        with alert_lock:
            if alert_type in active_alerts:
                active_alerts[alert_type]["email_status"] = "sent"

        logger.warning(
            f"NEW ALERT: {alert_type} - {reason}"
        )
        logger.info(
            f"Alert email sent to {recipient_email}: {alert_type}"
        )
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(
            f"SMTP authentication failed while sending {alert_type}: {e}"
        )
    except smtplib.SMTPException as e:
        logger.error(
            f"SMTP error while sending {alert_type}: {e}"
        )
    except (socket.timeout, socket.gaierror) as e:
        logger.error(
            f"SMTP connection error while sending {alert_type}: {e}"
        )
    except Exception as e:
        logger.error(
            f"Failed to send alert email for {alert_type}: {e}",
            exc_info=True
        )

    # Do not leave an alert active when its notification was not sent.
    with alert_lock:
        active_alerts.pop(alert_type, None)
    return False


def resolve_alert(alert_type):
    """Resolve an active alert so the same type can notify again later."""
    global active_alerts

    with alert_lock:
        if alert_type in active_alerts:
            logger.info(f"Alert resolved: {alert_type}")
            del active_alerts[alert_type]

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
    """Send registration OTP to the email entered by the user."""
    try:
        msg = MIMEText(
            f"""Hello,

Your AI-IDS registration verification code is:

{otp}

This OTP is valid for 5 minutes.

If you did not request this registration, you can safely ignore this email.

Regards,
AI-IDS Security System
"""
        )

        msg['Subject'] = 'AI-IDS Registration OTP'
        msg['From'] = Config.MAIL_USERNAME
        msg['To'] = email

        with smtplib.SMTP(
            Config.MAIL_SERVER,
            Config.MAIL_PORT,
            timeout=10
        ) as server:

            server.starttls()
            server.login(
                Config.MAIL_USERNAME,
                Config.MAIL_PASSWORD
            )

            server.send_message(msg)

        logger.info(f"Registration OTP sent to {email}")

        return True

    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}", exc_info=True)
        return False

def log_event(event_type, reason, session_id=None, session_data=None, client_ip=None, username=None):
    """Log an event with timestamp and optional session data.

    Email notification is intentionally handled by start_alert()/resolve_alert()
    so logging an event cannot create duplicate alert emails.
    """
    timestamp = datetime.now()
    entry = {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "reason": reason
    }

    if client_ip:
        entry["client_ip"] = client_ip

    if session_id:
        entry["session_id"] = session_id

    if session_data:
        entry["session_data"] = session_data

    logger.info(f"Event: {event_type} - {reason}")

    detection_log.append(entry)
    if len(detection_log) > 100:
        detection_log.pop(0)

    return entry

# Global variables
USERS = load_users()
camera = None
frame_lock = Lock()
current_frame = None
detection_log = []
active_alerts = {}
alert_lock = Lock()
video_writer = None
video_start_time = None
frame_count = 0
recording_enabled = False  # Temporarily disabled to prevent crashes
last_recording_restart = 0  # Track last restart time
recording_restart_count = 0  # Count restart attempts
runtime = {
    # Used by background CCTV threads because Flask session is unavailable
    # outside an HTTP request context.
    "active_username": None,
    "detection_enabled": True,
    "inject_enabled": False,
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
    "inject_attack_start_time": None,
    "inject_attack_session_id": None,
    "inject_attack_logged": False
}

# Camera management
def init_camera():
    global camera, runtime
    try:
        camera = cv2.VideoCapture(Config.CAMERA_INDEX, cv2.CAP_DSHOW)
        if camera.isOpened():
            runtime["camera_connected"] = True
            runtime["status"] = "Running"
            logger.info(f"Camera {Config.CAMERA_INDEX} initialized successfully")
            return True
        else:
            logger.error(f"Failed to open camera {Config.CAMERA_INDEX}")
            return False
    except Exception as e:
        logger.error(f"Camera initialization error: {str(e)}")
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

            # Preserve the logged-in user for background CCTV alert emails.
            runtime["active_username"] = username
            
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
            log_event("LOGIN_FAILED", f"Failed login attempt for {username}", client_ip=request.remote_addr, username=username)
            
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Capture username before clearing the Flask session.
    username = session.get('username')

    session.clear()
    runtime["active_username"] = None

    logger.info("User logged out")
    log_event("LOGOUT", "User logged out", username=username)
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
            return jsonify({
                "success": False,
                "message": "Failed to start camera"
            }), 500
    except Exception as e:
        logger.error(f"Error starting camera: {e}")
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

# Add these routes to your Flask app
@app.route('/api/start_detection', methods=['POST'])
@login_required
def start_detection():
    runtime["detection_enabled"] = True
    logger.info("Detection started")
    return jsonify({
        "status": "success",
        "message": "Detection started",
        "detection_enabled": True
    })


@app.route('/api/stop_detection', methods=['POST'])
@login_required
def stop_detection():
    runtime["detection_enabled"] = False
    logger.info("Detection stopped")
    return jsonify({
        "status": "success",
        "message": "Detection stopped",
        "detection_enabled": False
    })


@app.route('/api/detection_status', methods=['GET'])
@login_required
def detection_status():
    return jsonify({
        "running": runtime["detection_enabled"],
        "detection_enabled": runtime["detection_enabled"]
    })

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "detection_enabled": runtime["detection_enabled"],
        "inject_enabled": runtime["inject_enabled"],
        "manual_attack": runtime["manual_attack"],
        "status": runtime["status"],
        "camera_connected": runtime["camera_connected"],
        "last_alert_time": runtime["last_alert_time"],
        "sound_active": runtime["sound_active"],
        "log": detection_log,  # Return all logs to maintain complete history
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
            logger.info("Inject attack started")
            log_event("INJECT_ATTACK_TRIGGER", f"Inject attack triggered by {client_ip}", client_ip=client_ip, username=session.get('username'))
        else:
            # Stop inject attack - this will trigger session logging
            runtime["inject_enabled"] = False
            logger.info("Inject attack stopped")
    else:
        return jsonify({"error": f"Unknown action: {action}"}), 400
    
    return jsonify({"success": True, "action": action, "runtime": runtime})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    global detection_log
    
    # Detect suspicious log clearing
    client_ip = request.remote_addr
    logger.warning(f"Log clearing attempt from {client_ip}")
    log_event("SYSTEM_TAMPERING", f"Log clearing attempt by {client_ip}", client_ip=client_ip, username=session.get('username'))
    
    detection_log.clear()
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
        
        # Get all video files
        for filename in os.listdir(recordings_dir):
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
        else:
            obstruction_duration = current_time - runtime["obstruction_start_time"]
            
            # 5-second sound alert (start continuous sound)
            if obstruction_duration >= 5 and not runtime["sound_alert_played"]:
                logger.warning("Camera covered for 5 seconds - STARTING SOUND ALERT")
                # Don't log SOUND_ALERT separately - include in session summary
                runtime["sound_alert_played"] = True
                runtime["sound_active"] = True
            
            # 20-second notification
            if obstruction_duration >= 20 and not runtime["obstruction_notified"]:
                logger.error("🚨 CAMERA COVERED FOR 20 SECONDS - SENDING NOTIFICATION 🚨")
                # Don't log NOTIFICATION separately - include in session summary
                runtime["obstruction_notified"] = True
                
                # Always show console notification
                print("\n" + "="*60)
                print("🚨 CAMERA OBSTRUCTION ALERT 🚨")
                print(f"Camera has been covered for {obstruction_duration:.0f} seconds")
                print(f"Reason: {reason}")
                print("="*60 + "\n")
                
                # Send exactly one email for this active obstruction alert.
                start_alert(
                    "CAMERA_OBSTRUCTION",
                    reason,
                    session_data={
                        "duration": obstruction_duration,
                        "threshold_seconds": 20
                    },
                    username=None
                )
        
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
            
            # Resolve the alert so a future obstruction can generate a new email.
            resolve_alert("CAMERA_OBSTRUCTION")

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

            # Send one email for this active manual-attack incident.
            start_alert(
                "MANUAL_ATTACK",
                "Manual attack triggered",
                username=None
            )
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
                
                log_event("MANUAL_ATTACK_SESSION", f"Manual attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data, username=None)
                runtime["manual_attack_logged"] = True  # Mark as logged to prevent duplicates
            
            # Resolve the alert so a future manual attack can generate a new email.
            resolve_alert("MANUAL_ATTACK")

            # Reset all manual attack tracking variables
            runtime["manual_attack_start_time"] = None
            runtime["manual_attack_session_id"] = None
            runtime["manual_attack_logged"] = False
        
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

            # Send one email for this active video-injection incident.
            start_alert(
                "VIDEO_INJECTION",
                "Video injection attack detected",
                username=None
            )
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
                
                log_event("INJECT_ATTACK_SESSION", f"Inject attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data, username=None)
                runtime["inject_attack_logged"] = True  # Mark as logged to prevent duplicates
            
            # Resolve the alert so a future injection attack can generate a new email.
            resolve_alert("VIDEO_INJECTION")

            # Reset all inject attack tracking variables
            runtime["inject_attack_start_time"] = None
            runtime["inject_attack_session_id"] = None
            runtime["inject_attack_logged"] = False
        
# Email notifications for security incidents are handled by start_alert().

# Frame generation and processing
def gen_frames():
    global current_frame, runtime, video_writer, video_start_time
    prev_frame = None
    obstruction_count = 0
    
    # Start recording when camera initializes
    if recording_enabled and video_writer is None and runtime["camera_connected"]:
        start_new_recording()
    
    while True:
        if not runtime["camera_connected"]:
            if not init_camera():
                time.sleep(2)
                continue
            
            # Start recording when camera connects
            if recording_enabled and video_writer is None:
                start_new_recording()

        try:
            success, frame = camera.read()
            if not success or frame is None:
                logger.warning("Failed to read frame from camera, attempting to re-initialize.")
                release_camera() # Release existing camera
                time.sleep(1) # Wait a bit before trying to re-initialize
                runtime["camera_connected"] = False # Mark as disconnected to trigger re-init
                continue

            is_alert = False
            alert_reason = None
            annotated_frame = frame.copy()
            
            # Resize frame for consistent recording
            frame = cv2.resize(frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT))
            annotated_frame = cv2.resize(annotated_frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT))
            
            # Add timestamp to all frames for CCTV recording
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            annotated_frame = _add_annotation(annotated_frame, timestamp, (10, Config.FRAME_HEIGHT - 20), (255, 255, 255))
            
            # Process frame based on current state
            if runtime["inject_enabled"]:
                # Simulate video freeze/injection
                annotated_frame = _add_annotation(frame, "INJECT: FREEZE", (10, 50), (0, 165, 255))
                is_alert = True
                alert_reason = "Video injection attack detected"
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
                
                # Add status text
                if is_alert:
                    annotated_frame = _add_annotation(annotated_frame, f"ALERT: {alert_reason}", (10, 30), (0, 0, 255))
                    runtime["status"] = "ALERT"
                else:
                    annotated_frame = _add_annotation(annotated_frame, "Status: Monitoring", (10, 30), (0, 255, 0))
                    runtime["status"] = "Running"

            # Handle attack session timing
            current_time = time.time()
            
            # Update manual attack timing based on runtime flag
            handle_manual_attack_timing(runtime["manual_attack"], current_time)
            
            # Update inject attack timing based on runtime flag
            handle_inject_attack_timing(runtime["inject_enabled"], current_time)
            
            # Only log alerts that are not part of sessions
            if is_alert and alert_reason:
                # Don't log individual alerts that are handled by sessions
                if not (runtime["obstruction_start_time"] and 
                       ("obstructed" in alert_reason or "covered" in alert_reason)) and \
                   not (runtime["manual_attack_start_time"] and alert_reason == "Manual attack triggered") and \
                   not (runtime["inject_attack_start_time"] and alert_reason == "Inject attack triggered"):
                    log_event("ALERT", alert_reason)
            
            # Write frame to video file (CCTV recording)
            write_frame_to_video(annotated_frame)
            
            # Store previous frame for motion detection
            prev_frame = frame.copy()

            # Encode the frame for web streaming
            ret, buffer = cv2.imencode('.jpg', annotated_frame)
            if not ret:
                logger.warning("Failed to encode frame")
                continue

            frame_bytes = buffer.tobytes()
            with frame_lock:
                current_frame = frame_bytes

            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        except Exception as e:
            logger.error(f"Error in frame generation: {str(e)}")
            runtime["camera_connected"] = False
            time.sleep(1)

# Cleanup on exit
import atexit
@atexit.register
def cleanup():
    release_camera()
    logger.info("Application shutting down")

# Email test routes
@app.route('/test-email', methods=['GET'])
@app.route('/api/test-email', methods=['GET'])
def test_email_route():
    """Send a direct test email to the current user's registered email."""
    try:
        recipient_email = get_alert_email()

        logger.info("\n=== Starting Email Test ===")
        logger.info(f"Sender email: {Config.MAIL_USERNAME}")
        logger.info(f"Recipient email: {recipient_email}")
        logger.info(f"SMTP Server: {Config.MAIL_SERVER}:{Config.MAIL_PORT}")
        logger.info(f"Using TLS: {Config.MAIL_USE_TLS}")

        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            return "Gmail username or app password is not configured", 500

        if not recipient_email:
            return "No registered user email is available for the alert", 500

        msg = MIMEText(
            "This is a test email from the AI-IDS notification system.\n\n"
            "Your Gmail SMTP configuration is working correctly."
        )
        msg['Subject'] = '[AI-IDS] Email Configuration Test'
        msg['From'] = Config.MAIL_USERNAME
        msg['To'] = recipient_email

        start_time = time.time()
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)

        elapsed = time.time() - start_time
        logger.info(f"Test email sent successfully in {elapsed:.2f} seconds!")
        return f"Test email sent successfully to {recipient_email}."

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed. Check Gmail and the App Password.", exc_info=True)
        return "SMTP authentication failed. Check your Gmail address and App Password.", 500
    except smtplib.SMTPException as e:
        logger.error(f"SMTP Error: {e}", exc_info=True)
        return f"SMTP error: {e}", 500
    except (socket.timeout, socket.gaierror) as e:
        logger.error(f"SMTP connection error: {e}", exc_info=True)
        return f"SMTP connection error: {e}", 500
    except Exception as e:
        logger.error(f"Unexpected email test error: {e}", exc_info=True)
        return f"Email test failed: {e}", 500


@app.route('/test-email-alert')
def test_email_alert():
    """Trigger the normal de-duplicated alert-email path."""
    try:
        success = start_alert(
            "TEST_ALERT",
            "This is a test alert to verify AI-IDS alert notifications are working."
        )

        if success:
            return jsonify({
                "status": "success",
                "message": "Test alert email sent. Repeating this endpoint will not send another email until TEST_ALERT is resolved."
            }), 200

        return jsonify({
            "status": "already_active_or_failed",
            "message": "Test alert is already active or the email could not be sent."
        }), 500

    except Exception as e:
        logger.error(f"Error in test_email_alert: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Failed to send test alert: {str(e)}"
        }), 500


@app.route('/resolve-test-email-alert')
def resolve_test_email_alert():
    """Resolve the test alert so it can send again on the next test."""
    resolve_alert("TEST_ALERT")
    return jsonify({
        "status": "success",
        "message": "TEST_ALERT resolved. The next test alert can send a new email."
    })

if __name__ == '__main__':
    # Initialize AI-IDS system (camera will be started after login)
    logger.info("Initializing AI-IDS system...")
    logger.info("Camera will be initialized after user login")
    
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