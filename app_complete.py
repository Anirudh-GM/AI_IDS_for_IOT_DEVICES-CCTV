# app.py — Enhanced version with better error handling and features
from flask import Flask, render_template, Response, request, jsonify, send_from_directory
import cv2
import numpy as np
import time
import os
import json
from datetime import datetime
from threading import Lock
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    CAMERA_INDEX = 0
    FRAME_WIDTH = 640
    FRAME_HEIGHT = 480
    FPS = 20
    OBSTRUCTION_THRESHOLD = 0.85
    MOTION_THRESHOLD = 0.3
    ALERT_EMAIL = None  # Set to email address for notifications
    # CCTV Recording Configuration
    RECORDINGS_DIR = "recordings"
    VIDEO_DURATION = 300  # 5 minutes per video file (seconds)
    VIDEO_CODEC = 'mp4v'
    VIDEO_FPS = 20
    MOTION_DIFF_THRESHOLD = int(os.getenv("MOTION_DIFF_THRESHOLD", "2500"))
    BRIGHTNESS_LOW = int(os.getenv("BRIGHTNESS_LOW", "25"))
    COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
    ALERT_PHONE = os.getenv("ALERT_PHONE", "")
    UPLOAD_FOLDER = 'static/events'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure directories exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.RECORDINGS_DIR, exist_ok=True)

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
    return render_template('start_dashboard.html')

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
    
    if action == 'start':
        runtime["detection_enabled"] = True
        logger.info("Detection enabled via API")
    elif action == 'stop':
        runtime["detection_enabled"] = False
        logger.info("Detection disabled via API")
    elif action == 'toggle_manual':
        if not runtime["manual_attack"]:
            # Start manual attack
            runtime["manual_attack"] = True
            logger.info("Manual attack started")
        else:
            # Stop manual attack - this will trigger session logging
            runtime["manual_attack"] = False
            logger.info("Manual attack stopped")
    elif action == 'toggle_inject':
        if not runtime["inject_enabled"]:
            # Start inject attack
            runtime["inject_enabled"] = True
            logger.info("Inject attack started")
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
    detection_log.clear()
    logger.info("Logs cleared via API")
    return jsonify({"success": True, "message": "Logs cleared"})

@app.route('/api/recordings', methods=['GET'])
def list_recordings():
    """List all recorded video files"""
    try:
        recordings = []
        recordings_dir = Config.RECORDINGS_DIR
        
        # Get all video files
        for filename in os.listdir(recordings_dir):
            if filename.endswith('.mp4'):
                filepath = os.path.join(recordings_dir, filename)
                stat = os.stat(filepath)
                recordings.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    'download_url': f'/api/download/{filename}'
                })
        
        # Sort by creation time (newest first)
        recordings.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({"recordings": recordings})
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
                
                log_event("OBSTRUCTION_SESSION", f"Camera obstruction: {start_time} - {end_time} ({obstruction_duration:.1f}s)", session_data=summary_data)
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
            if not init_camera():
                time.sleep(2)
                continue
            
            # Start recording when camera connects
            if recording_enabled and video_writer is None:
                start_new_recording()

        try:
            success, frame = camera.read()
            if not success or frame is None:
                logger.warning("Failed to read frame from camera")
                runtime["camera_connected"] = False
                time.sleep(1)
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

if __name__ == '__main__':
    # Initialize camera
    init_camera()
    
    # Start the Flask app
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to start Flask: {str(e)}")
    finally:
        release_camera()
