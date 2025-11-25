import cv2, time, os, json, hashlib, threading, queue
from collections import deque
from flask import Flask, request, jsonify, Response
import winsound

# CONFIG
CAMERA_SOURCE = 0
OUTPUT_DIR = "evidence"
PRE_SECONDS = 3
POST_SECONDS = 3
TARGET_FPS = 12
FRAME_WIDTH = 320
BRIGHTNESS_COVER_THR = 40
BLUR_LAPLACE_THR = 80
FREEZE_DIFF_THR = 100
FREEZE_CONSEC = 6
DETECT_SKIP = 2

os.makedirs(OUTPUT_DIR, exist_ok=True)
app = Flask(__name__)

manual_attack = False
inject_attack = False
_flags_lock = threading.Lock()
clients = []
clients_lock = threading.Lock()

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def write_metadata(meta, outfile):
    with open(outfile,"w") as f:
        json.dump(meta, f, indent=2)

def resize_keep_aspect(frame, width=FRAME_WIDTH):
    (h,w) = frame.shape[:2]
    if w == width:
        return frame
    r = width/float(w)
    dim = (width, int(h*r))
    return cv2.resize(frame, dim)

class ThreadedCapture:
    def __init__(self, src=0, backend=cv2.CAP_DSHOW):
        self.cap = cv2.VideoCapture(src, backend)
        self.lock = threading.Lock()
        self.stopped = False
        self.frame = None
        self.ret = False
        t = threading.Thread(target=self.update, daemon=True)
        t.start()
    def update(self):
        while not self.stopped:
            ret, frame = self.cap.read()
            with self.lock:
                self.ret = ret
                self.frame = frame
            if not ret:
                time.sleep(0.05)
    def read(self):
        with self.lock:
            return self.ret, None if self.frame is None else self.frame.copy()
    def release(self):
        self.stopped = True
        time.sleep(0.1)
        try:
            self.cap.release()
        except:
            pass

def init_hog_detector():
    hog = cv2.HOGDescriptor()
    hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
    return hog

def detect_people_hog(hog, frame):
    rects, weights = hog.detectMultiScale(frame, winStride=(8,8), padding=(8,8), scale=1.07)
    boxes = []
    for (x,y,w,h), wt in zip(rects, weights):
        boxes.append((int(x),int(y),int(w),int(h), float(wt)))
    return boxes

def push_event(event_type, payload):
    msg = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "type": event_type, "payload": payload}
    s = json.dumps(msg)
    print("[EVENT]", s)`n    try:`n        if event_type == "detection": winsound.Beep(1000, 250)`n    except: pass
    with clients_lock:
        for q in list(clients):
            try:
                q.put(s, block=False)
            except:
                pass

@app.route('/remote_attack', methods=['POST','GET'])
def remote_attack():
    global manual_attack, inject_attack
    if request.method == 'GET':
        with _flags_lock:
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
    with _flags_lock:
        return jsonify({"manual": manual_attack, "inject": inject_attack})

@app.route('/events')
def sse_events():
    def gen(q):
        try:
            while True:
                s = q.get()
                yield f"data: {s}\\n\\n"
        except GeneratorExit:
            pass
    q = queue.Queue()
    with clients_lock:
        clients.append(q)
    with _flags_lock:
        init_status = {"manual": manual_attack, "inject": inject_attack}
    q.put(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "type": "init", "payload": init_status}))
    return Response(gen(q), mimetype='text/event-stream')

def camera_loop():
    cap = ThreadedCapture(CAMERA_SOURCE)
    hog = init_hog_detector()
    frame_buffer = deque(maxlen=PRE_SECONDS * TARGET_FPS + 5)
    prev_gray = None
    freeze_count = 0
    camera_id = "cam1"
    last_save_time = 0
    frame_idx = 0
    print("Fast camera loop started. Target FPS:", TARGET_FPS)
    try:
        while True:
            t0 = time.time()
            ret, frame = cap.read()
            if not ret or frame is None:
                time.sleep(0.02)
                continue

            frame_proc = resize_keep_aspect(frame, FRAME_WIDTH)
            try:
                cv2.imwrite('latest.jpg', frame_proc, [int(cv2.IMWRITE_JPEG_QUALITY), 65])
            except:
                pass

            gray = cv2.cvtColor(frame_proc, cv2.COLOR_BGR2GRAY)
            frame_buffer.append((time.time(), frame_proc.copy()))

            mean_brightness = float(gray.mean())
            covered = mean_brightness < BRIGHTNESS_COVER_THR
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

            boxes = []
            if (frame_idx % DETECT_SKIP) == 0:
                small = cv2.resize(frame_proc, (int(FRAME_WIDTH*0.8), int(frame_proc.shape[0]*0.8)))
                boxes = detect_people_hog(hog, small)
                if boxes:
                    sx = frame_proc.shape[1] / small.shape[1]
                    sy = frame_proc.shape[0] / small.shape[0]
                    boxes = [(int(x*sx), int(y*sy), int(w*sx), int(h*sy), s) for (x,y,w,h,s) in boxes]

            people_detected = len(boxes) > 0

            with _flags_lock:
                m_attack = manual_attack
                i_attack = inject_attack

            event_reasons = []
            if covered: event_reasons.append("camera_covered")
            if blurred: event_reasons.append("blur_detected")
            if freeze_event: event_reasons.append("camera_frozen")
            if people_detected: event_reasons.append("person_detected")
            if m_attack: event_reasons.append("manual_attack_active")
            if i_attack: event_reasons.append("inject_attack_active")

            now = time.time()
            if event_reasons and (now - last_save_time) > (PRE_SECONDS + POST_SECONDS - 0.5):
                pre_frames = list(frame_buffer)
                if len(pre_frames) > PRE_SECONDS * TARGET_FPS:
                    pre_frames = pre_frames[-(PRE_SECONDS*TARGET_FPS):]

                post_frames = []
                target_post = max(1, int(POST_SECONDS * TARGET_FPS))
                collected = 0
                while collected < target_post:
                    ret2, f2 = cap.read()
                    if not ret2 or f2 is None:
                        break
                    f2_proc = resize_keep_aspect(f2, FRAME_WIDTH)
                    post_frames.append((time.time(), f2_proc.copy()))
                    collected += 1
                    time.sleep(1.0 / float(TARGET_FPS))

                clip_frames = pre_frames + post_frames
                clip_path = None
                try:
                    if clip_frames:
                        h,w = clip_frames[0][1].shape[:2]
                        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
                        clip_path = os.path.join(OUTPUT_DIR, f"{camera_id}_{time.strftime('%Y%m%d_%H%M%S')}_event.mp4")
                        out = cv2.VideoWriter(clip_path, fourcc, TARGET_FPS, (w,h))
                        for _,f in clip_frames:
                            out.write(f)
                        out.release()
                except:
                    clip_path = None

                snap_paths = []
                if pre_frames:
                    snap_paths.append(os.path.join(OUTPUT_DIR, f"{camera_id}_{int(time.time())}_pre.jpg"))
                    cv2.imwrite(snap_paths[-1], pre_frames[0][1])
                if clip_frames:
                    mid = len(clip_frames)//2
                    snap_paths.append(os.path.join(OUTPUT_DIR, f"{camera_id}_{int(time.time())}_mid.jpg"))
                    cv2.imwrite(snap_paths[-1], clip_frames[mid][1])
                if post_frames:
                    snap_paths.append(os.path.join(OUTPUT_DIR, f"{camera_id}_{int(time.time())}_post.jpg"))
                    cv2.imwrite(snap_paths[-1], post_frames[-1][1])

                meta = {
                    "time": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "camera_id": camera_id,
                    "reasons": event_reasons,
                    "clip": clip_path,
                    "snapshots": snap_paths,
                    "mean_brightness": mean_brightness,
                    "laplacian_var": lap_var,
                    "people_count": len(boxes)
                }
                meta_fname = (clip_path + '.json') if clip_path else os.path.join(OUTPUT_DIR, f"{camera_id}_{int(time.time())}_meta.json")
                try:
                    write_metadata(meta, meta_fname)
                except:
                    pass
                push_event('detection', meta)
                print('EVENT SAVED:', meta_fname)
                last_save_time = now

            overlay = frame_proc.copy()
            status_text = []
            if covered: status_text.append('COVERED')
            if blurred: status_text.append('BLUR')
            if freeze_event: status_text.append('FROZEN')
            if people_detected: status_text.append(f'PERSONS:{len(boxes)}')
            if m_attack: status_text.append('MANUAL_ATTACK')
            if i_attack: status_text.append('INJECT_ATTACK')
            status = ' | '.join(status_text) if status_text else 'OK'
            color = (0,255,0) if not status_text else (0,140,255)
            cv2.putText(overlay, f'Status: {status}', (10,20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)
            for (x,y,w,h,score) in boxes:
                cv2.rectangle(overlay, (x,y), (x+w,y+h), (255,0,0), 1)

            cv2.imshow('CCTV Monitor (fast)', overlay)
            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                break

            frame_idx += 1
            elapsed = time.time() - t0
            sleep_for = max(0, (1.0/float(TARGET_FPS)) - elapsed)
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        print('Camera loop stopped')
    finally:
        cap.release()
        cv2.destroyAllWindows()

if __name__ == '__main__':
    t = threading.Thread(target=camera_loop, daemon=True)
    t.start()
    app.run(host='127.0.0.1', port=5000, threaded=True)
