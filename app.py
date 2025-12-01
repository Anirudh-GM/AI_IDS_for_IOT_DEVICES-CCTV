# app.py — Enhanced version with better error handling and features
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for
import cv2
import numpy as np
import time
import logging
import os
import threading
from datetime import datetime
from werkzeug.utils import secure_filename
import json
import hashlib
import re
from threading import Lock
from functools import wraps

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("python-dotenv not installed. Using system environment variables only.")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")  # Load from environment variable
    # CCTV Recording Configuration
    RECORDINGS_DIR = "recordings"
    VIDEO_DURATION = 300  # 5 minutes per video file (seconds)
    VIDEO_CODEC = 'mp4v'
    VIDEO_FPS = 20
    MOTION_DIFF_THRESHOLD = int(os.getenv("MOTION_DIFF_THRESHOLD", "2500"))
    BRIGHTNESS_LOW = int(os.getenv("BRIGHTNESS_LOW", "25"))
    COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))
    ALERT_PHONE = os.getenv("ALERT_PHONE", "")
    UPLOAD_FOLDER = 'static/events'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.RECORDINGS_DIR, exist_ok=True)

# User database (in production, use a proper database)
USERS = {}  # Start with no users - must be created with admin code

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

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def authenticate_user(username, password):
    """Authenticate user credentials"""
    user = USERS.get(username)
    if user and user['password'] == password:
        return user
    return None

def get_user_by_username(username):
    """Get user information by username"""
    return USERS.get(username)

# Global variables
camera = None
frame_lock = Lock()
current_frame = None
detection_log = []
video_writer = None
video_start_time = None
recording_enabled = True
runtime = {
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
    "inject_attack_logged": False,
    "camera_failure_count": 0,
    "last_camera_retry": 0,
    "camera_recovery_mode": False
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

def recover_camera():
    """Attempt to recover camera connection with exponential backoff"""
    global camera, runtime
    
    current_time = time.time()
    
    # Rate limit recovery attempts (minimum 2 seconds between attempts)
    if current_time - runtime["last_camera_retry"] < 2:
        return False
    
    runtime["last_camera_retry"] = current_time
    runtime["camera_failure_count"] += 1
    
    # Release existing camera instance
    if camera is not None:
        try:
            camera.release()
        except:
            pass
        camera = None
    
    # Exponential backoff: 2^failure_count seconds, max 30 seconds
    backoff_time = min(2 ** runtime["camera_failure_count"], 30)
    
    # Wait before retry
    time.sleep(min(backoff_time, 5))  # Cap wait at 5 seconds for responsiveness
    
    logger.info(f"Camera recovery attempt #{runtime['camera_failure_count']} (backoff: {backoff_time}s)")
    
    try:
        # Try different camera initialization methods
        camera = cv2.VideoCapture(Config.CAMERA_INDEX, cv2.CAP_DSHOW)
        if camera.isOpened():
            # Test if camera can actually read frames
            test_success, test_frame = camera.read()
            if test_success and test_frame is not None:
                runtime["camera_connected"] = True
                runtime["camera_failure_count"] = 0
                runtime["camera_recovery_mode"] = False
                runtime["status"] = "Running"
                logger.info("Camera recovered successfully")
                log_event("CAMERA_RECOVERED", f"Camera recovered after {runtime['camera_failure_count']} attempts")
                return True
            else:
                logger.warning("Camera opened but cannot read frames")
                camera.release()
                camera = None
        else:
            logger.warning(f"Failed to open camera {Config.CAMERA_INDEX}")
            
    except Exception as e:
        logger.error(f"Camera recovery error: {str(e)}")
        if camera is not None:
            try:
                camera.release()
            except:
                pass
            camera = None
    
    runtime["camera_connected"] = False
    runtime["camera_recovery_mode"] = True
    
    # If too many failures, suggest user intervention
    if runtime["camera_failure_count"] >= 5:
        logger.error("Camera recovery failed multiple times - may need physical check")
        log_event("CAMERA_FAILURE", f"Camera recovery failed after {runtime['camera_failure_count']} attempts")
        runtime["status"] = "Camera Recovery Needed"
    
    return False

def start_new_recording():
    """Start a new video recording file"""
    global video_writer, video_start_time
    
    # Stop existing recording
    if video_writer is not None:
        video_writer.release()
    
    # Create new video file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cctv_{timestamp}.mp4"
    filepath = os.path.join(Config.RECORDINGS_DIR, filename)
    
    # Initialize video writer
    fourcc = cv2.VideoWriter_fourcc(*Config.VIDEO_CODEC)
    video_writer = cv2.VideoWriter(
        filepath, 
        fourcc, 
        Config.VIDEO_FPS, 
        (Config.FRAME_WIDTH, Config.FRAME_HEIGHT)
    )
    
    video_start_time = time.time()
    logger.info(f"Started new recording: {filename}")
    return filepath

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
    global video_writer, video_start_time
    
    if not recording_enabled or video_writer is None:
        return
    
    # Write frame to video
    video_writer.write(frame)
    
    # Check if video duration exceeded
    current_time = time.time()
    if video_start_time and (current_time - video_start_time) >= Config.VIDEO_DURATION:
        # Start new recording file
        start_new_recording()

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
        username = data.get('username', '')
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        
        # Authenticate user
        user = authenticate_user(username, password)
        if user:
            # Set session
            session['user_id'] = username
            session['username'] = username
            session['email'] = user['email']
            session['role'] = user['role']
            session.permanent = remember_me
            
            logger.info(f"User logged in: {username}")
            log_event("LOGIN", f"User {username} logged in")
            
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": {
                    "username": username,
                    "email": user['email'],
                    "role": user['role']
                },
                "camera_initialized": runtime["camera_connected"]
            })
        else:
            logger.warning(f"Login failed for: {username}")
            log_event("LOGIN_FAILED", f"Failed login attempt for {username}")
            
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    logger.info("User logged out")
    log_event("LOGOUT", "User logged out")
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/create-user')
def create_user():
    # Allow access to create user page without login
    # Users need to create account before they can login
    return render_template('create-user.html')

@app.route('/api/verify-admin-code', methods=['POST'])
def verify_admin_code():
    """Verify admin code for user creation"""
    data = request.get_json()
    code = data.get('code', '')
    
    if code in ADMIN_CODES:
        return jsonify({
            "success": True,
            "message": "Admin code verified successfully"
        })
    else:
        logger.warning(f"Invalid admin code attempted: {code}")
        log_event("UNAUTHORIZED_ACCESS", f"Invalid admin code: {code}")
        return jsonify({
            "success": False,
            "message": "Invalid admin code"
        }), 403

@app.route('/api/create-user', methods=['POST'])
def api_create_user():
    """Create new user with admin code verification"""
    data = request.get_json()
    
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    email = data.get('email', '').strip()
    admin_code = data.get('admin_code', '')
    
    client_ip = request.remote_addr
    
    # Verify admin code
    if admin_code not in ADMIN_CODES:
        logger.warning(f"User creation attempt with invalid admin code from {client_ip}")
        log_event("UNAUTHORIZED_USER_CREATION", f"Invalid admin code from {client_ip}")
        return jsonify({
            "success": False,
            "message": "Invalid admin code"
        }), 403
    
    # Validate input
    if not username or not password or not email:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400
    
    if len(username) < 3:
        return jsonify({
            "success": False,
            "message": "Username must be at least 3 characters"
        }), 400
    
    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters"
        }), 400
    
    # Check if user already exists
    if username in USERS:
        return jsonify({
            "success": False,
            "message": "Username already exists"
        }), 400
    
    # Create new user - all users are administrators
    USERS[username] = {
        'password': password,  # In production, use hashed passwords
        'email': email,
        'role': 'Administrator',  # All users are administrators
        'member_since': datetime.now().strftime('%Y-%m-%d')
    }
    
    # Set this user's email as the default alert email if no email is configured
    if not Config.ALERT_EMAIL or Config.ALERT_EMAIL == "admin@example.com":
        Config.ALERT_EMAIL = email
        os.environ['ALERT_EMAIL'] = email
        logger.info(f"Alert email set to first user's email: {email}")
    
    # Remove used admin code
    del ADMIN_CODES[admin_code]
    
    logger.info(f"New administrator created: {username} from {client_ip}")
    log_event("ADMIN_CREATED", f"Administrator {username} created from {client_ip}")
    
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
        log_event("PROFILE_UPDATED", f"User {username} updated profile")
        
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
    log_event("PASSWORD_CHANGED", f"User {username} changed password")
    
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

@app.route('/api/settings/email', methods=['POST'])
def update_email_settings():
    """Update alert email settings"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({
                "success": False,
                "message": "Email address is required"
            }), 400
        
        # Basic email validation
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({
                "success": False,
                "message": "Invalid email address format"
            }), 400
        
        # Get current user from session
        username = session.get('username')
        if not username:
            return jsonify({
                "success": False,
                "message": "User not logged in"
            }), 401
        
        # Update user's email in the database
        if username in USERS:
            USERS[username]['email'] = email
            # Update session email too
            session['email'] = email
            
            logger.info(f"User {username} email updated to: {email}")
            log_event("SETTINGS_UPDATE", f"User {username} email set to {email}")
            
            return jsonify({
                "success": True,
                "message": "Email settings updated successfully",
                "email": email
            })
        else:
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
    except Exception as e:
        logger.error(f"Error updating email settings: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to update email settings"
        }), 500

@app.route('/api/settings/email', methods=['GET'])
def get_email_settings():
    """Get current email settings"""
    try:
        # Get current user's email from session
        user_email = session.get('email')
        
        # Fallback to Config.ALERT_EMAIL if no user session
        if not user_email:
            user_email = Config.ALERT_EMAIL
        
        return jsonify({
            "success": True,
            "email": user_email
        })
    except Exception as e:
        logger.error(f"Error getting email settings: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to get email settings"
        }), 500

@app.route('/api/camera/start', methods=['POST'])
@login_required
def api_camera_start():
    """Start camera and recording"""
    try:
        if init_camera():
            logger.info(f"Camera started by user: {session.get('username')}")
            start_new_recording()
            log_event("CAMERA_STARTED", f"Camera started by {session.get('username')}")
            
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
        log_event("CAMERA_STOPPED", f"Camera stopped by {username}")
        
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
    log_event("ADMIN_CODE_GENERATED", f"Admin code generated by {session.get('username')}")
    
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
            log_event("SUSPICIOUS_ACTIVITY", f"Rapid control requests from {client_ip}")
    
    control.last_control_time[key] = current_time
    control.control_count[key] = control.control_count.get(key, 0) + 1
    
    # Check for excessive control requests
    if control.control_count[key] > 10:
        logger.warning(f"Excessive control requests from {client_ip}: {control.control_count[key]} requests")
        log_event("BRUTE_FORCE_ATTEMPT", f"Excessive control requests from {client_ip}")
    
    if action == 'start':
        runtime["detection_enabled"] = True
        logger.info("Detection enabled via API")
    elif action == 'stop':
        runtime["detection_enabled"] = False
        logger.info("Detection disabled via API")
        log_event("SYSTEM_TAMPERING", f"Detection disabled by {client_ip}")
    elif action == 'toggle_manual':
        if not runtime["manual_attack"]:
            # Start manual attack
            runtime["manual_attack"] = True
            logger.info("Manual attack started")
            log_event("MANUAL_ATTACK_TRIGGER", f"Manual attack triggered by {client_ip}")
        else:
            # Stop manual attack - this will trigger session logging
            runtime["manual_attack"] = False
            logger.info("Manual attack stopped")
    elif action == 'toggle_inject':
        if not runtime["inject_enabled"]:
            # Start inject attack
            runtime["inject_enabled"] = True
            logger.info("Inject attack started")
            log_event("INJECT_ATTACK_TRIGGER", f"Inject attack triggered by {client_ip}")
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
    log_event("SYSTEM_TAMPERING", f"Log clearing attempt by {client_ip}")
    
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
        log_event("CONFIG_INJECTION", f"Config injection attempt by {client_ip}: {list(data.keys())}")
        
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
            log_event("CREDENTIAL_THEFT", f"File access attempt by {client_ip}: {requested_path}")
            return jsonify({"error": "Access denied"}), 403
    
    logger.info(f"File access from {client_ip}: {requested_path}")
    return jsonify({"error": "File not found"}), 404

@app.route('/api/exploit', methods=['POST'])
def exploit():
    """Exploit attempt detection"""
    client_ip = request.remote_addr
    data = request.get_json()
    
    logger.error(f"Exploit attempt from {client_ip}: {data}")
    log_event("EXPLOIT_ATTEMPT", f"Exploit attempt by {client_ip}: {data.get('exploit', 'unknown')}")
    
    return jsonify({"error": "Access denied"}), 403

@app.route('/api/version', methods=['GET'])
def version():
    """Version information disclosure detection"""
    client_ip = request.remote_addr
    
    logger.info(f"Version information requested by {client_ip}")
    log_event("RECONNAISSANCE", f"Version enumeration by {client_ip}")
    
    return jsonify({"version": "AI-IDS v1.0", "build": "secure"})

@app.route('/api/system', methods=['GET'])
def system_info():
    """System information disclosure detection"""
    client_ip = request.remote_addr
    
    logger.info(f"System information requested by {client_ip}")
    log_event("RECONNAISSANCE", f"System enumeration by {client_ip}")
    
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
    """Detect camera obstruction (lens covered by hand or any object) - More robust detection"""
    current_time = time.time()
    
    # Calculate average brightness
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    avg_brightness = cv2.mean(gray)[0]
    
    # Calculate standard deviation to detect uniform color
    mean, std_dev = cv2.meanStdDev(gray)
    std_dev_value = std_dev[0][0]
    
    is_obstructed = False
    reason = None
    
    # More lenient obstruction detection to avoid false positives
    # Check if extremely dark (camera completely covered)
    if avg_brightness < 10:  # Very dark threshold
        is_obstructed = True
        reason = f"Camera completely obstructed (brightness: {avg_brightness:.1f})"
    # Check for extremely uniform color (lens completely covered)
    elif std_dev_value < 5:  # Very low standard deviation means uniform color
        is_obstructed = True
        reason = f"Camera completely covered (low variance: {std_dev_value:.1f})"
    # Additional check: if brightness is extremely low
    elif avg_brightness < 5:  # Extremely dark
        is_obstructed = True
        reason = f"Camera severely obstructed (brightness: {avg_brightness:.1f})"
    
    return is_obstructed, reason

def handle_obstruction_timing(is_obstructed, reason, frame, current_time):
    """Handle the timing logic for obstruction alerts with proper camera continuity"""
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
            
            # Send email alert at the start of obstruction attack
            send_attack_email_alert("Camera Obstruction", reason, "obstruction")
        else:
            obstruction_duration = current_time - runtime["obstruction_start_time"]
            
            # 5-second sound alert (start continuous sound)
            if obstruction_duration >= 5 and not runtime["sound_alert_played"]:
                logger.warning("Camera covered for 5 seconds - STARTING SOUND ALERT")
                runtime["sound_alert_played"] = True
                runtime["sound_active"] = True
            
            # 20-second notification
            if obstruction_duration >= 20 and not runtime["obstruction_notified"]:
                logger.error(" CAMERA COVERED FOR 20 SECONDS - SENDING NOTIFICATION ")
                runtime["obstruction_notified"] = True
                
                # Always show console notification
                print("\n" + "="*60)
                print(" CAMERA OBSTRUCTION ALERT ")
                print(f"Camera has been covered for {obstruction_duration:.0f} seconds")
                print(f"Reason: {reason}")
                print("="*60 + "\n")
                
                # Send email notification if configured
                send_notification_email(reason, obstruction_duration)
        
        return True
    else:
        # Reset obstruction timer if camera is no longer obstructed
        if runtime["obstruction_start_time"] is not None:
            obstruction_duration = current_time - runtime["obstruction_start_time"]
            
            # Create summary log entry for the entire obstruction session (only once)
            if obstruction_duration > 1 and not runtime["session_logged"]:  # Only log if obstruction lasted more than 1 second and not already logged
                session_id = runtime.get("obstruction_session_id", datetime.now().strftime("%Y%m%d_%H%M%S"))
                start_time = datetime.fromtimestamp(runtime["obstruction_start_time"]).strftime("%H:%M:%S")
                
                logger.info(f"Camera obstruction session ended - Duration: {obstruction_duration:.1f}s")
                log_event("OBSTRUCTION_SESSION_END", 
                         f"Camera obstruction session ended - Duration: {obstruction_duration:.1f}s, "
                         f"Session ID: {session_id}, Start: {start_time}")
                
                runtime["session_logged"] = True  # Mark as logged to prevent duplicates
            
            # Reset all obstruction tracking variables
            runtime["obstruction_start_time"] = None
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
            
            # Send email alert at the start of manual attack
            send_attack_email_alert("Manual Attack", "Manual attack triggered by user", "manual")
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
                
                log_event("MANUAL_ATTACK_SESSION", f"Manual attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data)
                runtime["manual_attack_logged"] = True  # Mark as logged to prevent duplicates
            
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
            
            # Send email alert at the start of inject attack
            send_attack_email_alert("Inject Attack", "Inject attack triggered by user", "inject")
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
                    "reason": "Inject attack triggered"
                }
                
                log_event("INJECT_ATTACK_SESSION", f"Inject attack: {start_time} - {end_time} ({attack_duration:.1f}s)", session_data=summary_data)
                runtime["inject_attack_logged"] = True  # Mark as logged to prevent duplicates
            
            # Reset all inject attack tracking variables
            runtime["inject_attack_start_time"] = None
            runtime["inject_attack_session_id"] = None
            runtime["inject_attack_logged"] = False
        
        return False

def send_attack_email_alert(attack_type, reason, attack_category):
    """Send email alert at the start of an attack"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Get current user's email from session (if available)
        user_email = None
        try:
            from flask import session
            user_email = session.get('email')
            logger.info(f"User from session: {session.get('username')}")
        except RuntimeError:
            # Not in request context, fallback to Config.ALERT_EMAIL
            logger.warning("Not in request context, using fallback email")
        
        # Fallback to Config.ALERT_EMAIL if no user session
        if not user_email:
            user_email = Config.ALERT_EMAIL
        
        if not user_email:
            logger.warning("No user email available - notification not sent")
            return
        
        # Check Gmail credentials
        gmail_email = os.getenv('GMAIL_EMAIL')
        gmail_password = os.getenv('GMAIL_APP_PASSWORD')
        
        logger.info(f"Attempting to send email alert to: {user_email}")
        logger.info(f"Gmail configured: {bool(gmail_email and gmail_password)}")
        
        # Prepare email notification for attack start
        subject = f"[AI-IDS ALERT] {attack_type} Detected"
        body = f"""
        SECURITY ALERT - {attack_type}
        
        Attack Type: {attack_type}
        Reason: {reason}
        Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Category: {attack_category}
        
        This is an automated alert from your AI Intrusion Detection System.
        The attack has just been detected and monitoring is active.
        
        Please check the system immediately for details.
        
        --
        AI Intrusion Detection System
        Advanced CCTV Security Monitoring
        """
        
        # Log notification attempt
        logger.info(f"Preparing email with subject: {subject}")
        
        # Create message
        msg = MIMEText(body, 'plain')
        msg['Subject'] = subject
        msg['From'] = gmail_email or 'ai-ids@localhost'
        msg['To'] = user_email
        
        # Try Gmail first (more reliable)
        try:
            if gmail_email and gmail_password:
                logger.info("Attempting Gmail SMTP...")
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(gmail_email, gmail_password)
                msg['From'] = gmail_email
                server.send_message(msg)
                server.quit()
                logger.info(f"Attack alert email sent successfully via Gmail to {user_email}")
            else:
                logger.warning("Gmail credentials not configured, skipping Gmail attempt")
                raise Exception("Gmail not configured")
        except Exception as gmail_error:
            logger.error(f"Gmail SMTP failed: {gmail_error}")
            
            # Try local mail server as fallback
            try:
                logger.info("Attempting local SMTP as fallback...")
                server = smtplib.SMTP('localhost', 25)
                msg['From'] = 'ai-ids@localhost'
                server.send_message(msg)
                server.quit()
                logger.info(f"Attack alert email sent via local SMTP to {user_email}")
            except Exception as local_error:
                logger.error(f"Local SMTP also failed: {local_error}")
                raise Exception("Both email methods failed")
        
        # Log the alert event
        log_event("EMAIL_ALERT", f"{attack_type} alert sent to {user_email}")
        
    except Exception as e:
        logger.error(f"Error sending attack alert email: {e}")
        log_event("EMAIL_FAILED", f"Failed to send {attack_type} alert: {str(e)}")

def send_notification_email(reason, duration):
    """Send email notification about camera obstruction"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Check if email is configured
        if not Config.ALERT_EMAIL:
            logger.warning("No alert email configured - notification not sent")
            return
        
        # Prepare email notification
        subject = f"[AI-IDS] Camera Obstruction Alert - {duration:.0f} seconds"
        body = f"""
        Camera Obstruction Alert
        
        The camera has been obstructed for {duration:.0f} seconds.
        Reason: {reason}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Please check the camera immediately.
        
        --
        AI Intrusion Detection System
        """
        
        # Log notification attempt
        logger.info(f"Preparing email notification to: {Config.ALERT_EMAIL}")
        
        # Create message
        msg = MIMEText(body, 'plain')
        msg['Subject'] = subject
        msg['From'] = 'ai-ids@localhost'
        msg['To'] = Config.ALERT_EMAIL
        
        # Try to send using local SMTP or Gmail
        try:
            # Try local mail server first
            server = smtplib.SMTP('localhost', 25)
            server.send_message(msg)
            server.quit()
            logger.info(f"Email notification sent successfully via local SMTP")
        except:
            # Try Gmail if local fails (you'll need to configure this)
            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                # You need to set these environment variables:
                # GMAIL_EMAIL and GMAIL_APP_PASSWORD
                gmail_email = os.getenv('GMAIL_EMAIL')
                gmail_password = os.getenv('GMAIL_APP_PASSWORD')
                
                if gmail_email and gmail_password:
                    server.login(gmail_email, gmail_password)
                    msg['From'] = gmail_email
                    server.send_message(msg)
                    server.quit()
                    logger.info(f"Email notification sent successfully via Gmail")
                else:
                    logger.warning("Gmail credentials not configured - email not sent")
            except Exception as e2:
                logger.error(f"Failed to send email notification: {e2}")
                logger.info("To enable email notifications, configure SMTP settings or Gmail credentials")
        
    except Exception as e:
        logger.error(f"Failed to prepare notification email: {e}")

def log_event(event_type, reason, frame=None, session_id=None, session_data=None):
    """Log an intrusion event with optional session data"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    runtime["last_alert_time"] = ts
    
    entry = {
        "time": ts,
        "event_type": event_type,
        "reason": reason
    }
    
    # Add session data if provided
    if session_id:
        entry["session_id"] = session_id
    if session_data:
        entry["session_data"] = session_data
    
    # Photo capture disabled - not saving frames
    
    detection_log.append(entry)
    
    # Keep only last 100 events
    if len(detection_log) > 100:
        detection_log.pop(0)
    
    logger.info(f"Event logged: {event_type} - {reason}")

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
            # Try to recover camera connection
            if not recover_camera():
                # Generate placeholder frame while camera is disconnected
                placeholder = _make_placeholder(f"CAMERA RECOVERING... (Attempt {runtime['camera_failure_count']})")
                with frame_lock:
                    current_frame = placeholder
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + placeholder + b'\r\n')
                time.sleep(0.1)  # Short sleep to prevent CPU spinning
                continue
            
            # Start recording when camera recovers
            if recording_enabled and video_writer is None:
                start_new_recording()

        try:
            success, frame = camera.read()
            if not success or frame is None:
                logger.warning("Failed to read frame from camera")
                runtime["camera_connected"] = False
                time.sleep(0.1)  # Brief pause before recovery attempt
                continue

            # Validate frame quality before processing
            if frame.size == 0 or frame.shape[0] == 0 or frame.shape[1] == 0:
                logger.warning("Invalid frame dimensions")
                runtime["camera_connected"] = False
                time.sleep(0.1)
                continue

            is_alert = False
            alert_reason = None
            annotated_frame = frame.copy()
            
            # Resize frame for consistent recording
            try:
                frame = cv2.resize(frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT))
                annotated_frame = cv2.resize(annotated_frame, (Config.FRAME_WIDTH, Config.FRAME_HEIGHT))
            except Exception as e:
                logger.error(f"Frame resize error: {e}")
                runtime["camera_connected"] = False
                continue
            
            # Add timestamp to all frames for CCTV recording
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            annotated_frame = _add_annotation(annotated_frame, timestamp, (10, Config.FRAME_HEIGHT - 20), (255, 255, 255))
            
            # Add recovery indicator if we just recovered
            if runtime["camera_recovery_mode"]:
                annotated_frame = _add_annotation(annotated_frame, "CAMERA RECOVERED", (10, 50), (0, 255, 0))
                runtime["camera_recovery_mode"] = False
            
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
                    # Add obstruction indicator but continue processing
                    annotated_frame = _add_annotation(annotated_frame, "OBSTRUCTION DETECTED", (10, 70), (0, 0, 255))
                
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
            time.sleep(0.1)  # Brief pause before recovery attempt

# Cleanup on exit
import atexit
@atexit.register
def cleanup():
    release_camera()
    logger.info("Application shutting down")

if __name__ == '__main__':
    # Initialize AI-IDS system (camera will be started after login)
    logger.info("Initializing AI-IDS system...")
    logger.info("Camera will be initialized after user login")
    
    # Start the Flask application
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        logger.info("Shutting down AI-IDS system...")
    finally:
        release_camera()
