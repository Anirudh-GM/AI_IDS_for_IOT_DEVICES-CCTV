# AIoT Guardian - Important Code Snippets for Report

## 1. Attack Detection Module

### 1.1 Frame Freeze Detection
```python
def detect_frame_freeze(self, frame):
    """
    Detect frame freeze (last frame repeated)
    Returns: (is_frozen, confidence, details)
    """
    # Calculate frame hash
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    frame_hash = hashlib.md5(gray.tobytes()).hexdigest()
    
    # Check if same frame repeated
    if self.last_frame_hash == frame_hash:
        self.freeze_count += 1
        if self.freeze_count >= 15:  # 15 consecutive identical frames
            return True, 0.9, f"Frame freeze detected: {self.freeze_count} identical frames"
    else:
        self.freeze_count = 0
    
    self.last_frame_hash = frame_hash
    return False, 0.0, "Normal frame variation"
```

**Pseudo-code:**
```
1. Convert frame to grayscale
2. Calculate MD5 hash of frame
3. Compare with previous frame hash
4. If identical, increment freeze counter
5. If freeze_count >= 15, trigger alert
6. Return detection result with confidence score
```

### 1.2 Video Injection Detection
```python
def detect_video_injection(self, frame, timestamp):
    """
    Detect video injection (fake feed replaces real video)
    Uses: Frame hashing, timestamp validation, motion estimation
    """
    # Store frame with timestamp
    self.frame_history.append({
        'frame': frame.copy(),
        'timestamp': timestamp,
        'hash': hashlib.md5(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).tobytes()).hexdigest()
    })
    
    # Check for repeated identical frames
    if len(self.frame_history) >= 7:
        recent_hashes = [f['hash'] for f in frame_list[-7:]]
        unique_hashes = len(set(recent_hashes))
        
        # If 5+ out of 7 frames are identical
        if unique_hashes <= 2:
            # Calculate motion variance
            motion_variance = np.var(list(self.motion_history)[-5:])
            if motion_variance < 5:  # Very low motion
                return True, 0.9, "Video injection detected"
    
    # Check for timestamp anomalies
    timestamps = [f['timestamp'] for f in self.frame_history]
    time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    abnormal_gaps = [diff for diff in time_diffs if abs(diff - avg_diff) > avg_diff * 4.0]
    
    if len(abnormal_gaps) >= 2:
        return True, 0.85, "Timestamp anomalies detected"
    
    return False, 0.0, "Normal video stream"
```

**Pseudo-code:**
```
1. Store frame with timestamp and hash
2. Analyze last 7 frames for repetition
3. Calculate motion variance
4. Check for timestamp gaps
5. If suspicious patterns detected, return attack alert
```

### 1.3 Network Attack Detection - Port Scanning
```python
def detect_port_scan(self, client_ip, port, endpoint):
    """
    Detect port scanning (reconnaissance)
    Returns: (is_scan, confidence, details)
    """
    if client_ip not in self.ip_activity:
        self.ip_activity[client_ip] = {
            'ports': set(),
            'endpoints': set(),
            'requests': 0,
            'first_seen': time.time()
        }
    
    activity = self.ip_activity[client_ip]
    activity['ports'].add(port)
    activity['endpoints'].add(endpoint)
    activity['requests'] += 1
    
    time_window = time.time() - activity['first_seen']
    
    # Multiple ports accessed in short time
    if len(activity['ports']) > 10 and time_window < 30:
        return True, 0.9, f"Port scan detected: {len(activity['ports'])} ports in {time_window:.1f}s"
    
    # Multiple endpoints accessed rapidly
    if len(activity['endpoints']) > 20 and time_window < 15:
        return True, 0.85, f"Reconnaissance detected: {len(activity['endpoints'])} endpoints scanned"
    
    return False, 0.0, "Normal network activity"
```

**Pseudo-code:**
```
1. Track IP activity (ports, endpoints, request count)
2. Calculate time window since first request
3. If >10 ports accessed in <30 seconds → Port scan
4. If >20 endpoints accessed in <15 seconds → Reconnaissance
5. Return detection result
```

### 1.4 DoS Flood Detection
```python
def detect_dos_flood(self, client_ip, request_time):
    """
    Detect DoS flood (camera overload)
    Returns: (is_dos, confidence, details)
    """
    self.dos_patterns[client_ip].append(request_time)
    requests = list(self.dos_patterns[client_ip])
    
    if len(requests) < 10:
        return False, 0.0, "Insufficient data"
    
    # Calculate request rate
    time_window = requests[-1] - requests[0]
    request_rate = len(requests) / time_window if time_window > 0 else 0
    
    # High request rate (DoS indicator)
    if request_rate > 10:  # 10 requests per second
        return True, 0.9, f"DoS flood detected: {request_rate:.1f} req/s"
    
    # Burst pattern
    recent_requests = [r for r in requests if request_time - r < 5]
    if len(recent_requests) > 30:  # 30 requests in 5 seconds
        return True, 0.85, f"DoS burst detected: {len(recent_requests)} requests in 5s"
    
    return False, 0.0, "Normal request rate"
```

**Pseudo-code:**
```
1. Track request timestamps per IP
2. Calculate request rate (requests/second)
3. If rate > 10 req/s → DoS flood
4. If >30 requests in 5 seconds → DoS burst
5. Return detection result
```

---

## 2. Network IDS Module (Machine Learning)

### 2.1 Model Training - Random Forest
```python
def train_random_forest(self, X_train, y_train, n_estimators=100, max_depth=20):
    """Train Random Forest classifier"""
    self.model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=42,
        n_jobs=-1
    )
    
    self.model.fit(X_train, y_train)
    self.is_trained = True
```

**Pseudo-code:**
```
1. Initialize Random Forest with 100 trees, max depth 20
2. Fit model on training data (X_train, y_train)
3. Mark model as trained
4. Model can now predict normal (0) vs attack (1)
```

### 2.2 Model Training - Deep Neural Network
```python
def train_dnn(self, X_train, y_train, epochs=50, batch_size=32):
    """Train Deep Neural Network"""
    input_dim = X_train.shape[1]
    
    self.model = Sequential([
        Dense(128, activation='relu', input_dim=input_dim),
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(1, activation='sigmoid')  # Binary classification
    ])
    
    self.model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    self.model.fit(X_train, y_train, epochs=epochs, batch_size=batch_size)
    self.is_trained = True
```

**Pseudo-code:**
```
1. Create sequential DNN model:
   - Input layer (128 neurons, ReLU)
   - Dropout (30%)
   - Hidden layer 1 (64 neurons, ReLU)
   - Dropout (30%)
   - Hidden layer 2 (32 neurons, ReLU)
   - Dropout (20%)
   - Output layer (1 neuron, Sigmoid)
2. Compile with Adam optimizer, binary crossentropy loss
3. Train for 50 epochs with batch size 32
4. Model ready for prediction
```

### 2.3 Real-time Traffic Analysis
```python
def analyze_network_traffic(self, traffic_features):
    """
    Analyze network traffic in real-time
    Args:
        traffic_features: Dictionary or DataFrame with network traffic features
    """
    # Convert to DataFrame
    df = pd.DataFrame([traffic_features])
    
    # Ensure feature order matches training
    df = df.reindex(columns=self.feature_names, fill_value=0)
    
    # Predict
    prediction = self.predict(df)
    probabilities = self.predict_proba(df)
    
    result = {
        'prediction': 'attack' if prediction[0] == 1 else 'normal',
        'confidence': float(probabilities[0][1] if prediction[0] == 1 else probabilities[0][0]),
        'timestamp': datetime.now().isoformat()
    }
    
    return result
```

**Pseudo-code:**
```
1. Convert traffic features to DataFrame
2. Align features with training data
3. Preprocess (normalize) features
4. Predict using trained model
5. Get prediction probability
6. Return result: 'attack' or 'normal' with confidence score
```

---

## 3. Attack Recovery Module

### 3.1 Attack Recording and Mitigation
```python
def record_attack_start(self, attack_type, client_ip=None, details=None, duration=None):
    """Record that an attack has started"""
    attack_id = f"{attack_type}_{int(time.time())}"
    attack_state = {
        'start_time': time.time(),
        'client_ip': client_ip,
        'details': details,
        'recovered': False,
        'duration': duration
    }
    
    self.attack_states[attack_type][attack_id] = attack_state
    
    # Apply immediate mitigation
    if client_ip:
        self._apply_mitigation(attack_type, client_ip)

def _apply_mitigation(self, attack_type, client_ip):
    """Apply immediate mitigation measures - BLOCKS IP to stop attack"""
    # Block IP immediately
    block_duration = self.recovery_cooldowns.get(attack_type, 60) * 2
    self.blocked_ips[client_ip] = time.time() + block_duration
```

**Pseudo-code:**
```
1. Generate unique attack ID
2. Record attack state (start time, IP, details)
3. If duration provided, schedule auto-end
4. Apply immediate mitigation:
   - Block attacker IP
   - Block duration = 2x recovery cooldown
5. Log attack detection
```

### 3.2 Recovery Process
```python
def check_and_recover(self):
    """Check if any attacks can be recovered from"""
    current_time = time.time()
    
    # Check for attacks that should auto-end
    for attack_type, attacks in self.attack_states.items():
        for attack_id, state in list(attacks.items()):
            if state.get('auto_end_scheduled') and state.get('expected_end_time'):
                if current_time >= state['expected_end_time']:
                    # Auto-end the attack
                    state['end_time'] = current_time
                    self._schedule_recovery(attack_type, attack_id, state)
    
    # Check all attack states for recovery (after cooldown)
    for attack_type, attacks in self.attack_states.items():
        for attack_id, state in list(attacks.items()):
            if state.get('recovery_scheduled') and not state.get('recovered'):
                recovery_time = state.get('recovery_time', 0)
                if current_time >= recovery_time:
                    # Perform recovery
                    self._perform_recovery(attack_type, attack_id, state)
    
    # Unblock IPs that have served their time
    for ip in list(self.blocked_ips.keys()):
        if current_time >= self.blocked_ips[ip]:
            del self.blocked_ips[ip]
```

**Pseudo-code:**
```
1. Get current time
2. For each active attack:
   a. Check if auto-end time reached → schedule recovery
   b. Check if recovery time reached → perform recovery
3. For each blocked IP:
   a. If block time expired → unblock IP
4. Clean up old attack records (>1 hour)
```

### 3.3 Recovery Actions
```python
def _perform_recovery(self, attack_type, attack_id, attack_state):
    """Perform recovery procedure for a specific attack"""
    recovery_actions = []
    
    if attack_type in ['DDOS', 'DOS_FLOOD']:
        recovery_actions.append("Rate limit counters reset")
        recovery_actions.append("Network traffic monitoring resumed")
    
    elif attack_type in ['VIDEO_INJECTION']:
        recovery_actions.append("Video injection mode disabled")
        recovery_actions.append("Frame validation reset")
        recovery_actions.append("Normal video feed resumed")
    
    elif attack_type in ['PORT_SCAN']:
        recovery_actions.append("Port scan detection cleared")
        recovery_actions.append("Normal endpoint access resumed")
    
    # Mark as recovered
    attack_state['recovered'] = True
    attack_state['recovery_actions'] = recovery_actions
    
    return recovery_summary
```

**Pseudo-code:**
```
1. Determine attack type
2. Execute recovery actions:
   - DoS/DDoS: Reset rate limits, resume monitoring
   - Video Injection: Reset frame validation, resume feed
   - Port Scan: Clear detection, resume access
3. Mark attack as recovered
4. Log recovery completion
```

---

## 4. Main Application - Authentication

### 4.1 User Authentication
```python
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

@app.route('/login', methods=['POST'])
def login():
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Authenticate user
    user = authenticate_user(username, password)
    if user:
        # Set session
        session['user_id'] = user['username']
        session['username'] = user['username']
        session['role'] = user.get('role', 'user')
        
        log_event("LOGIN", f"User {username} logged in", client_ip=request.remote_addr)
        return jsonify({"success": True, "message": "Login successful"})
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
```

**Pseudo-code:**
```
1. Get username and password from request
2. Load users from JSON file
3. Hash provided password (SHA-256)
4. Compare with stored hash
5. If match:
   - Create session
   - Store user info in session
   - Log login event
   - Return success
6. Else: Return error
```

### 4.2 Login Required Decorator
```python
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('start_dashboard.html')
```

**Pseudo-code:**
```
1. Check if 'user_id' exists in session
2. If not → redirect to login page
3. If yes → execute protected route
```

---

## 5. Main Application - Video Processing

### 5.1 Continuous Detection Loop
```python
def run_detection_loop():
    """Continuous detection loop - runs independently of video feed requests"""
    global current_frame, prev_frame, frame_counter
    
    while True:
        try:
            ret, frame = camera.read()
            if not ret:
                continue
            
            frame_counter += 1
            
            # Comprehensive Attack Detection (run every 10th frame)
            if ATTACK_DETECTION_ENABLED and frame_counter % 10 == 0:
                attack_detector = get_attack_detector()
                current_timestamp = time.time()
                
                # Frame Freeze Detection
                freeze_detected, freeze_confidence, freeze_details = \
                    attack_detector.detect_frame_freeze(frame)
                if freeze_detected and freeze_confidence > 0.85:
                    log_event("FRAME_FREEZE", freeze_details)
                
                # Video Injection Detection
                injection_detected, injection_confidence, injection_details = \
                    attack_detector.detect_video_injection(frame, current_timestamp)
                if injection_detected and injection_confidence > 0.85:
                    log_event("VIDEO_INJECTION", injection_details)
            
            # Check and perform recovery
            if recovery_manager and frame_counter % 100 == 0:
                recovered = recovery_manager.check_and_recover()
                for attack_type, attack_id in recovered:
                    log_event("RECOVERY_COMPLETE", f"System recovered from {attack_type}")
            
            # Encode frame for streaming
            ret, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            current_frame = frame_bytes
            
            time.sleep(0.01)  # ~100 FPS max
            
        except Exception as e:
            logger.error(f"Error in detection loop: {e}")
            time.sleep(1)
```

**Pseudo-code:**
```
1. Start infinite loop
2. Read frame from camera
3. Every 10th frame:
   a. Run frame freeze detection
   b. Run video injection detection
   c. Log if attack detected
4. Every 100th frame:
   a. Check for recovery opportunities
   b. Perform recovery if needed
5. Encode frame for web streaming
6. Store frame for streaming
7. Sleep briefly (maintain ~100 FPS)
```

### 5.2 Video Feed Streaming
```python
def gen_frames():
    """Generate frames for video feed - uses latest frame from detection loop"""
    global current_frame
    
    while True:
        with frame_lock:
            frame = current_frame
        if frame:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        else:
            time.sleep(0.1)

@app.route('/video_feed')
@login_required
def video_feed():
    """Video streaming route"""
    return Response(gen_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
```

**Pseudo-code:**
```
1. Continuously yield frames in MJPEG format
2. Read latest frame from shared variable
3. Format as HTTP multipart response
4. Stream to client browser
5. Client displays video feed
```

---

## 6. Network Attack Detection Integration

### 6.1 Request-Level Attack Detection
```python
@app.route('/api/control', methods=['POST'])
def control():
    client_ip = request.remote_addr
    request_time = time.time()
    
    # Network Attack Detection
    if ATTACK_DETECTION_ENABLED:
        network_detector = get_network_attack_detector()
        
        # Detect Port Scan
        port = request.environ.get('SERVER_PORT', 5000)
        endpoint = request.path
        scan_detected, scan_confidence, scan_details = \
            network_detector.detect_port_scan(client_ip, port, endpoint)
        if scan_detected and scan_confidence > 0.85:
            log_event("PORT_SCAN", scan_details, client_ip=client_ip)
            recovery_manager.record_attack_start("PORT_SCAN", client_ip, scan_details)
        
        # Detect DoS Flood
        dos_detected, dos_confidence, dos_details = \
            network_detector.detect_dos_flood(client_ip, request_time)
        if dos_detected and dos_confidence > 0.85:
            log_event("DOS_FLOOD", dos_details, client_ip=client_ip)
            recovery_manager.record_attack_start("DOS_FLOOD", client_ip, dos_details)
    
    # Process request normally
    # ...
```

**Pseudo-code:**
```
1. Extract client IP and request time
2. For each request:
   a. Check for port scan patterns
   b. Check for DoS flood patterns
3. If attack detected:
   a. Log attack event
   b. Record attack start
   c. Apply mitigation (block IP)
4. Continue processing request
```

---

## 7. Key Algorithms Summary

### 7.1 Frame Hash Comparison Algorithm
```
Algorithm: Frame Freeze Detection
Input: Current frame
Output: (is_frozen, confidence, details)

1. Convert frame to grayscale
2. Calculate MD5 hash: hash = MD5(frame_bytes)
3. Compare with previous_hash
4. If hash == previous_hash:
     freeze_count++
     if freeze_count >= 15:
         return (True, 0.9, "Frame freeze detected")
5. Else:
     freeze_count = 0
6. previous_hash = hash
7. Return (False, 0.0, "Normal")
```

### 7.2 Port Scan Detection Algorithm
```
Algorithm: Port Scan Detection
Input: client_ip, port, endpoint
Output: (is_scan, confidence, details)

1. Track IP activity:
   - ports: set of accessed ports
   - endpoints: set of accessed endpoints
   - requests: request count
   - first_seen: timestamp

2. Add current (port, endpoint) to tracking
3. time_window = current_time - first_seen

4. If len(ports) > 10 AND time_window < 30:
     return (True, 0.9, "Port scan detected")
5. If len(endpoints) > 20 AND time_window < 15:
     return (True, 0.85, "Reconnaissance detected")
6. Return (False, 0.0, "Normal")
```

### 7.3 ML-Based Traffic Classification
```
Algorithm: Network Traffic Classification
Input: traffic_features (dictionary)
Output: (prediction, confidence)

1. Convert features to DataFrame
2. Align features with training data columns
3. Normalize features using StandardScaler
4. Predict using trained model:
   - Random Forest: model.predict(features)
   - DNN: model.predict(features) > 0.5
5. Get prediction probability
6. Return:
   - prediction: 'attack' or 'normal'
   - confidence: probability score
```

### 7.4 Attack Recovery Algorithm
```
Algorithm: Attack Recovery
Input: attack_type, attack_id, attack_state
Output: recovery_summary

1. Determine recovery actions based on attack_type:
   - DoS/DDoS: Reset rate limits
   - Video Injection: Reset frame validation
   - Port Scan: Clear detection state
   
2. Execute recovery actions
3. Mark attack_state['recovered'] = True
4. Schedule IP unblock (after cooldown period)
5. Log recovery completion
6. Return recovery_summary
```

---

## 8. Data Structures

### 8.1 Attack State Structure
```python
attack_state = {
    'start_time': float,          # Unix timestamp
    'end_time': float,            # Unix timestamp (if ended)
    'client_ip': str,             # Attacker IP address
    'details': str,               # Attack description
    'recovered': bool,            # Recovery status
    'duration': float,             # Attack duration in seconds
    'recovery_scheduled': bool,   # Recovery scheduled flag
    'recovery_time': float,       # Scheduled recovery timestamp
    'recovery_actions': list      # List of recovery actions taken
}
```

### 8.2 Network Traffic Features
```python
traffic_features = {
    'duration': float,            # Connection duration
    'protocol_type': int,         # Protocol (TCP/UDP/ICMP)
    'service': int,               # Service type
    'src_bytes': int,             # Source bytes
    'dst_bytes': int,             # Destination bytes
    'count': int,                 # Number of connections
    'srv_count': int,             # Number of service connections
    # ... (41 total features for NSL-KDD)
}
```

---

## 9. Configuration Parameters

### 9.1 Detection Thresholds
```python
# Frame Freeze Detection
FREEZE_THRESHOLD = 15              # Consecutive identical frames
FREEZE_CONFIDENCE = 0.85           # Minimum confidence for alert

# Video Injection Detection
INJECTION_FRAME_WINDOW = 7         # Frames to analyze
INJECTION_MOTION_THRESHOLD = 5     # Motion variance threshold
INJECTION_CONFIDENCE = 0.85        # Minimum confidence

# Port Scan Detection
PORT_SCAN_THRESHOLD = 10           # Number of ports
PORT_SCAN_TIME_WINDOW = 30         # Time window in seconds
ENDPOINT_SCAN_THRESHOLD = 20       # Number of endpoints

# DoS Detection
DOS_RATE_THRESHOLD = 10            # Requests per second
DOS_BURST_THRESHOLD = 30           # Requests in 5 seconds
```

### 9.2 Recovery Cooldowns
```python
recovery_cooldowns = {
    'DDOS': 60,                    # 1 minute
    'DOS_FLOOD': 60,               # 1 minute
    'PORT_SCAN': 30,               # 30 seconds
    'BRUTE_FORCE': 600,            # 10 minutes
    'VIDEO_INJECTION': 30,         # 30 seconds
    'FRAME_FREEZE': 60,            # 1 minute
    'MOTION_MASKING': 60,          # 1 minute
}
```

---

## 10. Integration Flow

### 10.1 System Initialization
```
1. Load Flask application
2. Initialize attack detection modules
3. Initialize network IDS module
4. Initialize recovery manager
5. Start camera capture
6. Start detection loop (background thread)
7. Register routes and blueprints
8. Start Flask server
```

### 10.2 Attack Detection Flow
```
1. Request/Frame arrives
2. Extract features (IP, port, endpoint, frame data)
3. Run detection algorithms:
   - Frame-based: freeze, injection, masking
   - Network-based: port scan, DoS, brute force
4. If attack detected:
   a. Log attack event
   b. Record attack start
   c. Apply mitigation (block IP)
   d. Schedule recovery
5. Continue normal operation
```

### 10.3 Recovery Flow
```
1. Attack ends (auto-end or manual)
2. Wait for cooldown period
3. Check recovery conditions
4. Execute recovery actions:
   - Reset detection counters
   - Clear blocked IPs
   - Resume normal operations
5. Mark attack as recovered
6. Log recovery completion
```

---

## Notes for Report

1. **Security Features**: The system implements multi-layered security with both rule-based and ML-based detection.

2. **Real-time Processing**: Detection runs continuously in background threads, ensuring minimal latency.

3. **Automatic Recovery**: System automatically recovers from attacks after cooldown periods, reducing manual intervention.

4. **Scalability**: ML models can be trained on various datasets (NSL-KDD, UNSW-NB15, IoT-23) for different environments.

5. **Modularity**: Code is organized into separate modules (detection, recovery, network IDS) for maintainability.

6. **Performance**: Optimized frame processing (every 10th frame for detection) balances accuracy and performance.


