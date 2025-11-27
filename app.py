# app.py — replacement (overwrite the whole file with this)
from flask import Flask, render_template, Response, request, jsonify
import cv2
import numpy as np
import time
import os
from cctv_app import CameraStream
from realtime_video_ids import IDSState
from notify import notify_async

app = Flask(__name__)

# Camera index (default 0). You can set environment variable CAMERA_INDEX to change it.
CAM_IDX = int(os.getenv("CAMERA_INDEX", "0"))
camera = CameraStream(src=CAM_IDX)

# IDS state (12s sustained obstruction by default)
ids = IDSState(obstruction_seconds=int(os.getenv("OBSTRUCTION_SECONDS", "12")),
               motion_diff_threshold=int(os.getenv("MOTION_DIFF_THRESHOLD", "2500")),
               brightness_low=int(os.getenv("BRIGHTNESS_LOW", "25")),
               cooldown_seconds=int(os.getenv("COOLDOWN_SECONDS", "300")))

# Runtime toggles and state
runtime = {
    "detection_enabled": True,
    "inject_enabled": False,
    "manual_attack": False,
    "status": "Stopped",
    "last_alert_time": None
}

detection_log = []  # in-memory log

# Alert contacts from env
ALERT_EMAIL = os.getenv("ALERT_EMAIL")   # single email or comma-separated
ALERT_PHONE = os.getenv("ALERT_PHONE")   # phone for SMS if configured

@app.route('/')
def index():
    return render_template('start_dashboard.html')

@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/start_detection', methods=['POST'])
def start_detection():
    runtime["detection_enabled"] = True
    runtime["status"] = "Running"
    return jsonify(success=True)

@app.route('/stop_detection', methods=['POST'])
def stop_detection():
    runtime["detection_enabled"] = False
    runtime["status"] = "Stopped"
    return jsonify(success=True)

@app.route('/toggle_manual', methods=['POST'])
def toggle_manual():
    runtime["manual_attack"] = not runtime["manual_attack"]
    return jsonify(manual=runtime["manual_attack"])

@app.route('/toggle_inject', methods=['POST'])
def toggle_inject():
    runtime["inject_enabled"] = not runtime["inject_enabled"]
    return jsonify(inject=runtime["inject_enabled"])

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "detection_enabled": runtime["detection_enabled"],
        "inject_enabled": runtime["inject_enabled"],
        "manual_attack": runtime["manual_attack"],
        "status": runtime["status"],
        "last_alert_time": runtime["last_alert_time"],
        "log": detection_log[-20:]
    })

def _make_placeholder(msg="NO CAMERA"):
    """Return JPEG bytes for a placeholder image."""
    img = np.zeros((360, 640, 3), dtype=np.uint8)
    cv2.putText(img, msg, (20, 180), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 0, 255), 2, cv2.LINE_AA)
    ret, buf = cv2.imencode('.jpg', img)
    return buf.tobytes() if ret else b''

NO_CAM_BYTES = _make_placeholder()

def gen_frames():
    """Generator to yield MJPEG frames to the browser."""
    last_frame_bytes = None
    while True:
        success, frame = camera.read()
        if not success or frame is None:
            # yield placeholder so the browser shows something
            if last_frame_bytes:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + last_frame_bytes + b'\r\n')
            else:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + NO_CAM_BYTES + b'\r\n')
            time.sleep(0.1)
            continue

        # Simulate injection/freeze when inject_enabled is True
        if runtime["inject_enabled"]:
            annotated = frame.copy()
            cv2.putText(annotated, "INJECT: FREEZE", (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 165, 255), 2, cv2.LINE_AA)
            ret, buffer = cv2.imencode('.jpg', annotated)
            if ret:
                last_frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + last_frame_bytes + b'\r\n')
            time.sleep(0.05)
            continue

        # If detection disabled, annotate and stream without IDS checks
        if not runtime["detection_enabled"]:
            annotated = frame.copy()
            cv2.putText(annotated, "Status: Detection OFF", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2, cv2.LINE_AA)
            ret, buffer = cv2.imencode('.jpg', annotated)
            if ret:
                last_frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + last_frame_bytes + b'\r\n')
            time.sleep(0.05)
            continue

        # Run IDS processing
        try:
            annotated, is_alert, reason = ids.process_frame(frame)
        except Exception as e:
            print("IDS error:", e)
            annotated = frame
            is_alert = False
            reason = None

        # Manual attack forces an alert (testing)
        if runtime["manual_attack"]:
            is_alert = True
            reason = "Manual attack toggled"

        # Handle alert: log and notify (non-blocking)
        if is_alert:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            runtime["last_alert_time"] = ts
            runtime["status"] = "ALERT"
            entry = {"time": ts, "reason": reason}
            detection_log.append(entry)
            if len(detection_log) > 500:
                detection_log.pop(0)

            # notifications (background thread)
            subject = "[AI-IDS] Camera Obstruction Alert"
            body = f"Alert: {reason}\nTime: {ts}\n"
            # email_to can be comma-separated
            email_to = ALERT_EMAIL
            if email_to:
                notify_async(subject, body, email_to=email_to, sms_to=ALERT_PHONE)
        else:
            runtime["status"] = "Running"

        # encode and yield
        try:
            ret, buffer = cv2.imencode('.jpg', annotated)
            if not ret:
                time.sleep(0.05)
                continue
            last_frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + last_frame_bytes + b'\r\n')
        except Exception as e:
            print("Encode error:", e)
            time.sleep(0.05)
            continue

if __name__ == '__main__':
    # Ensure OpenCV warnings don't crash the app; run Flask
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)
