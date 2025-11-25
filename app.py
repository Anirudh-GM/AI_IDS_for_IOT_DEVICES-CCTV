from flask import Flask, render_template, Response, jsonify, request
import cv2, threading, time, sqlite3
from datetime import datetime

app = Flask(__name__)

# Globals
camera = cv2.VideoCapture(0)
running = False
manual_attack = False
inject_attack = False
inject_until = 0
intrusion_detected = False
last_detected = None
db_lock = threading.Lock()

# DB helper (optional logging)
def log_intrusion(device, attack_type):
    with db_lock:
        conn = sqlite3.connect('intrusion_log.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device TEXT,
                attack_type TEXT
            )
        ''')
        cursor.execute("INSERT INTO intrusions (timestamp, device, attack_type) VALUES (?, ?, ?)",
                       (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), device, attack_type))
        conn.commit()
        conn.close()

# Inject helper
def start_inject(duration=8):
    global inject_attack, inject_until
    inject_attack = True
    inject_until = time.time() + duration
    def _wait():
        global inject_attack
        while time.time() < inject_until:
            time.sleep(0.1)
        inject_attack = False
    threading.Thread(target=_wait, daemon=True).start()

# Frame generator with detection logic
def generate_frames():
    global intrusion_detected, last_detected, inject_attack
    COVER_THRESHOLD = 40        # mean brightness below -> considered covered (tweakable)
    while True:
        success, frame = camera.read()
        if not success:
            time.sleep(0.1)
            continue

        # make a copy for analysis
        small = cv2.resize(frame, (320, 240))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        mean_brightness = int(gray.mean())

        # determine detection conditions
        now = time.time()
        is_covered = mean_brightness < COVER_THRESHOLD
        is_manual = manual_attack
        is_inject = inject_attack and (now < inject_until)

        # decide intrusion
        if is_manual:
            intrusion_type = "Manual Attack (A)"
            intrusion = True
            device = "Camera"
        elif is_inject:
            intrusion_type = "Injected Attack (I)"
            intrusion = True
            device = "Camera"
        elif is_covered:
            intrusion_type = "Camera Covered"
            intrusion = True
            device = "Camera"
        else:
            intrusion = False
            intrusion_type = ""
            device = ""

        # Set global state & log only on new detection
        if intrusion and (last_detected != intrusion_type):
            intrusion_detected = True
            last_detected = intrusion_type
            try:
                log_intrusion(device, intrusion_type)
            except Exception:
                pass
        elif not intrusion:
            intrusion_detected = False
            last_detected = None

        # Overlay status on frame
        status = "DETECTING" if running else "STOPPED"
        if intrusion:
            text = f"ALERT: {intrusion_type}"
            color = (0, 0, 255)
        else:
            text = f"Status: {status} | Brightness={mean_brightness}"
            color = (0, 255, 0)

        cv2.putText(frame, text, (10,30), cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 2)
        cv2.putText(frame, f"Manual(A)={'ON' if manual_attack else 'OFF'} Inject(I)={'ON' if inject_attack else 'OFF'}", (10,60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200,200,200), 1)

        ret, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

# Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/start_detection', methods=['POST'])
def start_detection():
    global running
    running = True
    return jsonify({'status':'started'})

@app.route('/stop_detection', methods=['POST'])
def stop_detection():
    global running, manual_attack, inject_attack
    running = False
    manual_attack = False
    inject_attack = False
    return jsonify({'status':'stopped'})

@app.route('/toggle_manual', methods=['POST'])
def toggle_manual():
    global manual_attack
    manual_attack = not manual_attack
    return jsonify({'manual': manual_attack})

@app.route('/inject', methods=['POST'])
def inject():
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 8))
    start_inject(duration)
    return jsonify({'injected': True, 'duration': duration})

@app.route('/get_status')
def get_status():
    # Return detection state and last intrusion info
    conn = sqlite3.connect('intrusion_log.db')
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, device, attack_type FROM intrusions ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    timestamp, device, attack_type = (row if row is not None else (None, None, None))
    return jsonify({
        'running': running,
        'manual_attack': manual_attack,
        'inject_attack': inject_attack and time.time() < inject_until,
        'intrusion_detected': intrusion_detected,
        'timestamp': timestamp,
        'device': device,
        'attack_type': attack_type
    })

if __name__ == '__main__':
    # ensure DB exists
    with db_lock:
        conn = sqlite3.connect('intrusion_log.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS intrusions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT, device TEXT, attack_type TEXT)''')
        conn.commit()
        conn.close()

    print('Starting app on http://127.0.0.1:5000')
    app.run(debug=True)
