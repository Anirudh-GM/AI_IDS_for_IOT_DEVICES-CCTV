import cv2
import time
import os
import json
import hashlib
import threading
import queue
import winsound
from collections import deque
from flask import Flask, request, jsonify, Response, send_from_directory

# ----------------- CONFIG -----------------
CAMERA_SOURCE = 0          # 0 = default webcam, change if using USB/RTSP
OUTPUT_DIR = "evidence"
PRE_SECONDS = 5
POST_SECONDS = 5
FPS = 8                    # lower FPS reduces CPU usage
FRAME_WIDTH = 640

BRIGHTNESS_COVER_THR = 40
BLUR_LAPLACE_THR = 80
FREEZE_DIFF_THR = 25
FREEZE_CONSEC = 6
# ------------------------------------------

os.makedirs(OUTPUT_DIR, exist_ok=True)
app = Flask(__name__)

manual_attack = False
inject_attack = False
_flags_lock = threading.Lock()
clients = []
clients_lock = threading.Lock()

def push_event(event_type, payload):
    msg = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "type": event_type, "payload": payload}
    s = json.dumps(msg)
    print("[EVENT]", s)

    # Sound alert for detection (Windows)
    if event_type == "detection":
        try:
            winsound.Beep(1200, 200)
        except:
            pass

    # push SSE to connected dashboard clients
    with clients_lock:
        for q in list(clients):
            try:
                q.put(s, block=False)
            except:
                pass

def resize_keep_aspect(frame, width=FRAME_WIDTH):
    h, w = frame.shape[:2]
    if w == width:
        return frame
    r = width / float(w)
    return cv2.resize(frame, (width, int(h * r)))

def init_hog_detector():
    hog = cv2.HOGDescriptor()
    hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
    return hog

def detect_people_hog(hog, frame):
    # run on a copy to be safe
    rects, weights = hog.detectMultiScale(frame, winStride=(8,8), padding=(8,8), scale=1.05)
    boxes = []
    for (x,y,w,h), wt in zip(rects, weights):
        boxes.append((int(x),int(y),int(w),int(h), float(wt)))
    return boxes

@app.route('/remote_attack', methods=['POST','GET'])
def remote_attack():
    global manual_attack, inject_attack
    if request.method == 'GET':
        return jsonify({"manual": manual_attack, "inject": inject_attack})
    data = request.get_json(force=True, silent=True) or {}
    changed = {}
    with _flags_lock:
        if 'manual' in data:
            manual_attack = bool(data['manual']); changed['manual'] = manual_attack
        if 'inject' in data:
            inject_attack = bool(data['inject']); changed['inject'] = inject_attack
        if 'toggle_manual' in data and data['toggle_manual']:
            manual_attack = not manual_attack; changed['manual'] = manual_attack
        if 'toggle_inject' in data and data['toggle_inject']:
            inject_attack = not inject_attack; changed['inject'] = inject_attack
    if changed:
        push_event("attack_flags_changed", changed)
    return jsonify({"status":"ok","manual":manual_attack,"inject":inject_attack})

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"manual": manual_attack, "inject": inject_attack})

@app.route('/events')
def sse_events():
    def gen(q):
        try:
            while True:
                s = q.get()
                yield f"data: {s}\n\n"
        except GeneratorExit:
            pass
    q = queue.Queue()
    with clients_lock:
        clients.append(q)
    q.put(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "type": "init", "payload": {"manual": manual_attack, "inject": inject_attack}}))
    return Response(gen(q), mimetype='text/event-stream')

# Serve dashboard.html from project folder at /dashboard
@app.route('/dashboard')
def dashboard():
    return send_from_directory(os.getcwd(), 'dashboard.html')

def camera_loop():
    cap = cv2.VideoCapture(CAMERA_SOURCE, cv2.CAP_DSHOW)
    if not cap.isOpened():
        print("ERROR: camera not available. Check CAMERA_SOURCE.")
        return

    hog = init_hog_detector()
    prev_gray = None
    freeze_count = 0
    last_event_time = 0

    frame_buffer = deque(maxlen=PRE_SECONDS * FPS)

    print("Camera loop started (headless). Writing latest.jpg for dashboard...")

    while True:
        ret, frame = cap.read()
        if not ret or frame is None:
            time.sleep(0.2)
            continue

        frame_proc = resize_keep_aspect(frame)
        # write low-res preview for the dashboard (fast)
        try:
            cv2.imwrite('latest.jpg', frame_proc, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
        except:
            pass

        gray = cv2.cvtColor(frame_proc, cv2.COLOR_BGR2GRAY)
        brightness = float(gray.mean())
        covered = brightness < BRIGHTNESS_COVER_THR

        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        blurred = lap_var < BLUR_LAPLACE_THR

        freeze_event = False
        if prev_gray is not None:
            diff = cv2.absdiff(gray, prev_gray)
            mean_diff = float(diff.mean())
            if mean_diff < FREEZE_DIFF_THR:
                freeze_count += 1
            else:
                freeze_count = 0
            if freeze_count >= FREEZE_CONSEC:
                freeze_event = True
        prev_gray = gray

        # detect people on smaller frame occasionally to save CPU
        boxes = detect_people_hog(hog, frame_proc)
        people_detected = len(boxes) > 0

        with _flags_lock:
            m_attack = manual_attack
            i_attack = inject_attack

        reasons = []
        if covered: reasons.append("camera_covered")
        if blurred: reasons.append("blur_detected")
        if freeze_event: reasons.append("camera_frozen")
        if people_detected: reasons.append("person_detected")
        if m_attack: reasons.append("manual_attack_active")
        if i_attack: reasons.append("inject_attack_active")

        now = time.time()
        if reasons and (now - last_event_time) > (PRE_SECONDS + POST_SECONDS - 0.5):
            meta = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "camera_id": "cam1",
                "reasons": reasons,
                "mean_brightness": brightness,
                "laplacian_var": lap_var,
                "people_count": len(boxes)
            }
            # save one snapshot for evidence
            try:
                snap_path = os.path.join(OUTPUT_DIR, f"cam1_{int(time.time())}_snap.jpg")
                cv2.imwrite(snap_path, frame_proc)
                meta["snapshot"] = snap_path
            except:
                pass

            push_event("detection", meta)
            last_event_time = now

        # pacing
        time.sleep(1.0 / FPS)

    # never reaches here normally
    cap.release()

if __name__ == '__main__':
    t = threading.Thread(target=camera_loop, daemon=True)
    t.start()
    app.run(host='127.0.0.1', port=5000, threaded=True)
