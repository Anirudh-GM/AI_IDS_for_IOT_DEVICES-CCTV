"""
Comprehensive Attack Detection Module
Detects all attack types from the security requirements
"""

import cv2
import numpy as np
import time
import hashlib
from datetime import datetime
from collections import deque
import logging

logger = logging.getLogger(__name__)

class AttackDetector:
    """Comprehensive attack detection for CCTV/IoT systems"""
    
    def __init__(self):
        self.frame_history = deque(maxlen=30)  # Store last 30 frames
        self.frame_hashes = deque(maxlen=100)  # Store frame hashes for freeze detection
        self.last_frame_hash = None
        self.freeze_count = 0
        self.motion_history = deque(maxlen=10)
        # Cooldown to prevent repeated alerts
        self.last_alert_time = {}
        self.alert_cooldown = 60  # 60 seconds cooldown between same type alerts
        
    def detect_frame_freeze(self, frame):
        """
        Detect frame freeze (last frame repeated)
        Returns: (is_frozen, confidence, details)
        """
        current_time = time.time()
        alert_type = "FRAME_FREEZE"
        
        # Check cooldown
        if alert_type in self.last_alert_time:
            if current_time - self.last_alert_time[alert_type] < self.alert_cooldown:
                return False, 0.0, "In cooldown period"
        
        # Calculate frame hash
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        frame_hash = hashlib.md5(gray.tobytes()).hexdigest()
        
        # Check if same frame repeated (increased threshold to reduce false positives)
        if self.last_frame_hash == frame_hash:
            self.freeze_count += 1
            if self.freeze_count >= 15:  # Increased from 5 to 15 consecutive identical frames
                self.last_alert_time[alert_type] = current_time
                return True, 0.9, f"Frame freeze detected: {self.freeze_count} identical frames"
        else:
            self.freeze_count = 0
        
        self.last_frame_hash = frame_hash
        self.frame_hashes.append(frame_hash)
        
        # Check for hash repetition pattern (possible injection) - more strict
        if len(self.frame_hashes) >= 30:  # Increased from 10 to 30
            unique_hashes = len(set(self.frame_hashes))
            if unique_hashes < 2:  # More strict: only 1-2 unique frames in 30
                self.last_alert_time[alert_type] = current_time
                return True, 0.85, "Possible frame freeze: Low frame diversity detected"
        
        return False, 0.0, "Normal frame variation"
    
    def detect_video_injection(self, frame, timestamp):
        """
        Detect video injection (fake feed replaces real video)
        Uses: Frame hashing, timestamp validation, motion estimation
        Made stricter to reduce false positives
        """
        current_time = time.time()
        alert_type = "VIDEO_INJECTION"
        
        # Check cooldown (increased to prevent false positives - 120 seconds for video injection)
        video_injection_cooldown = 120  # Longer cooldown for video injection to reduce false positives
        if alert_type in self.last_alert_time:
            if current_time - self.last_alert_time[alert_type] < video_injection_cooldown:
                return False, 0.0, "In cooldown period"
        
        # Store frame with timestamp
        self.frame_history.append({
            'frame': frame.copy(),
            'timestamp': timestamp,
            'hash': hashlib.md5(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).tobytes()).hexdigest()
        })
        
        # Require more frames for better baseline (reduced false positives)
        if len(self.frame_history) < 10:  # Increased from 3 to 10 for better baseline
            return False, 0.0, "Insufficient data"
        
        # Check for repeated identical frames (most reliable indicator)
        # Require more consecutive identical frames to reduce false positives
        if len(self.frame_history) >= 7:  # Increased from 3 to 7
            frame_list = list(self.frame_history)
            recent_hashes = [f['hash'] for f in frame_list[-7:]]  # Check last 7 frames
            unique_hashes = len(set(recent_hashes))
            
            # Only alert if 5+ out of 7 frames are identical (very suspicious)
            if unique_hashes <= 2:  # At most 2 unique hashes in 7 frames
                # Additional check: ensure this is not just a static scene
                # Calculate motion variance to distinguish static scene from injection
                if len(self.motion_history) >= 5:
                    motion_variance = np.var(list(self.motion_history)[-5:])
                    # If motion variance is very low AND frames are identical, likely injection
                    if motion_variance < 5:  # Very low motion variance
                        self.last_alert_time[alert_type] = current_time
                        return True, 0.9, "Repeated identical frames with zero motion detected (possible video injection)"
        
        # Check for sudden timestamp jumps (more strict threshold)
        timestamps = [f['timestamp'] for f in self.frame_history]
        if len(timestamps) >= 10:
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if len(time_diffs) >= 5:
                avg_diff = np.mean(time_diffs)
                std_diff = np.std(time_diffs)
                
                # More strict: require multiple abnormal gaps, not just one
                abnormal_gaps = [diff for diff in time_diffs if abs(diff - avg_diff) > avg_diff * 4.0]  # Increased from 2.5x to 4.0x
                
                # Require at least 2 abnormal gaps to reduce false positives
                if len(abnormal_gaps) >= 2 and std_diff > avg_diff * 0.5:  # High variance indicates real anomaly
                    self.last_alert_time[alert_type] = current_time
                    return True, 0.85, "Multiple suspicious timestamp anomalies detected (possible injection)"
        
        # Check for motion inconsistency (more strict)
        if len(self.frame_history) >= 5:
            prev_frame = self.frame_history[-2]['frame']
            motion = self._calculate_motion(prev_frame, frame)
            self.motion_history.append(motion)
            
            # Require more motion history for better baseline
            if len(self.motion_history) >= 10:  # Increased from 5 to 10
                avg_motion = np.mean(list(self.motion_history)[:-3])  # Use older frames for baseline
                recent_motions = list(self.motion_history)[-3:]  # Check last 3 frames
                avg_recent_motion = np.mean(recent_motions)
                
                # More strict: require sustained motion drop, not just one frame
                # Original motion must be significant AND recent motion must be near zero
                if avg_motion > 30 and avg_recent_motion < 3:  # Increased thresholds: 30 (was 20) and 3 (was 2)
                    # Additional check: ensure this is not just a temporary pause
                    if all(m < 5 for m in recent_motions):  # All 3 recent frames have very low motion
                        self.last_alert_time[alert_type] = current_time
                        return True, 0.8, "Sustained motion drop detected (possible video injection)"
        
        return False, 0.0, "Normal video stream"
    
    def _calculate_motion(self, prev_frame, current_frame):
        """Calculate motion between frames"""
        gray_prev = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
        gray_curr = cv2.cvtColor(current_frame, cv2.COLOR_BGR2GRAY)
        
        diff = cv2.absdiff(gray_prev, gray_curr)
        motion = np.sum(diff > 30)  # Count pixels with significant change
        
        return motion
    
    def detect_motion_masking(self, frame, prev_frame=None):
        """
        Detect motion masking (laser prevents detection)
        Checks for unusual brightness patterns that might indicate masking
        """
        current_time = time.time()
        alert_type = "MOTION_MASKING"
        
        # Check cooldown
        if alert_type in self.last_alert_time:
            if current_time - self.last_alert_time[alert_type] < self.alert_cooldown:
                return False, 0.0, "In cooldown period"
        
        if prev_frame is None:
            return False, 0.0, "No previous frame"
        
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray_prev = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
        
        # Check for localized bright spots (possible laser masking) - more strict
        diff = cv2.absdiff(gray, gray_prev)
        bright_spots = np.sum((gray > 200) & (diff < 10))  # Bright but no change
        
        if bright_spots > frame.shape[0] * frame.shape[1] * 0.3:  # Increased from 10% to 30% of frame
            self.last_alert_time[alert_type] = current_time
            return True, 0.7, f"Possible motion masking: {bright_spots} bright static pixels detected"
        
        # Check for unusual brightness patterns - more strict
        brightness_variance = np.var(gray)
        if brightness_variance < 20:  # More strict: decreased from 50 to 20
            self.last_alert_time[alert_type] = current_time
            return True, 0.65, "Unusual brightness uniformity (possible masking)"
        
        return False, 0.0, "Normal brightness pattern"


class NetworkAttackDetector:
    """Network-based attack detection"""
    
    def __init__(self):
        self.request_history = deque(maxlen=1000)
        self.ip_activity = {}  # Track activity per IP
        self.port_scan_patterns = {}
        self.dos_patterns = {}
        # Cooldown to prevent repeated alerts
        self.last_alert_time = {}
        self.alert_cooldown = 60  # 60 seconds cooldown between same type alerts
        self.network_alert_cooldown = 300  # 5 minutes for network attacks
        
    def detect_port_scan(self, client_ip, port, endpoint):
        """
        Detect port scanning (reconnaissance)
        Returns: (is_scan, confidence, details)
        """
        key = f"{client_ip}:{port}"
        
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
        
        # Check for port scan pattern
        time_window = time.time() - activity['first_seen']
        
        # Check cooldown
        alert_key = f"{client_ip}:PORT_SCAN"
        current_time = time.time()
        if alert_key in self.last_alert_time:
            if current_time - self.last_alert_time[alert_key] < self.network_alert_cooldown:
                return False, 0.0, "In cooldown period"
        
        # Multiple ports accessed in short time (more strict)
        if len(activity['ports']) > 10 and time_window < 30:  # Increased from 5 to 10 ports, decreased time from 60s to 30s
            self.last_alert_time[alert_key] = current_time
            return True, 0.9, f"Port scan detected: {len(activity['ports'])} ports in {time_window:.1f}s"
        
        # Multiple endpoints accessed rapidly (more strict)
        if len(activity['endpoints']) > 20 and time_window < 15:  # Increased from 10 to 20 endpoints, decreased time from 30s to 15s
            self.last_alert_time[alert_key] = current_time
            return True, 0.85, f"Reconnaissance detected: {len(activity['endpoints'])} endpoints scanned"
        
        return False, 0.0, "Normal network activity"
    
    def detect_dos_flood(self, client_ip, request_time):
        """
        Detect DoS flood (camera overload)
        Returns: (is_dos, confidence, details)
        """
        if client_ip not in self.dos_patterns:
            self.dos_patterns[client_ip] = deque(maxlen=100)
        
        self.dos_patterns[client_ip].append(request_time)
        requests = list(self.dos_patterns[client_ip])
        
        if len(requests) < 10:
            return False, 0.0, "Insufficient data"
        
        # Check request rate
        time_window = requests[-1] - requests[0]
        request_rate = len(requests) / time_window if time_window > 0 else 0
        
        # Check cooldown
        alert_key = f"{client_ip}:DOS_FLOOD"
        current_time = time.time()
        if alert_key in self.last_alert_time:
            if current_time - self.last_alert_time[alert_key] < self.network_alert_cooldown:
                return False, 0.0, "In cooldown period"
        
        # High request rate (DoS indicator) - lowered threshold for better detection
        if request_rate > 10:  # Lowered from 20 to 10 requests per second for better detection
            self.last_alert_time[alert_key] = current_time
            return True, 0.9, f"DoS flood detected: {request_rate:.1f} req/s from {client_ip}"
        
        # Burst pattern - lowered threshold
        recent_requests = [r for r in requests if request_time - r < 5]
        if len(recent_requests) > 30:  # Lowered from 100 to 30 requests in 5 seconds
            self.last_alert_time[alert_key] = current_time
            return True, 0.85, f"DoS burst detected: {len(recent_requests)} requests in 5s"
        
        # Check for rapid consecutive requests (even more sensitive)
        if len(requests) >= 5:
            time_span = requests[-1] - requests[-5] if len(requests) >= 5 else 1
            if time_span < 1.0 and len(requests) >= 5:  # 5+ requests in less than 1 second
                self.last_alert_time[alert_key] = current_time
                return True, 0.8, f"DoS rapid requests detected: {len(requests)} requests in {time_span:.2f}s"
        
        return False, 0.0, "Normal request rate"
    
    def detect_unauthorized_access(self, client_ip, login_attempts, success):
        """
        Detect unauthorized access attempts
        Returns: (is_unauthorized, confidence, details)
        """
        if client_ip not in self.ip_activity:
            return False, 0.0, "No activity"
        
        # Multiple failed login attempts - more strict
        if not success and login_attempts > 5:  # Increased from 3 to 5
            return True, 0.9, f"Unauthorized access attempt: {login_attempts} failed logins from {client_ip}"
        
        # Rapid login attempts (brute force) - more strict
        activity = self.ip_activity[client_ip]
        if activity['requests'] > 30 and time.time() - activity['first_seen'] < 30:  # Increased from 20 to 30, decreased time from 60s to 30s
            return True, 0.8, f"Brute force attempt: {activity['requests']} requests in <30s"
        
        return False, 0.0, "Normal access pattern"
    
    def detect_web_exploit(self, endpoint, payload):
        """
        Detect web exploits (configuration hacking)
        Returns: (is_exploit, confidence, details)
        """
        # Common exploit patterns
        exploit_patterns = [
            'union select', 'drop table', 'exec(', 'eval(',
            '../', '..\\', 'script>', '<iframe',
            'javascript:', 'onerror=', 'onload=',
            'cmd=', 'system(', 'shell_exec'
        ]
        
        payload_lower = str(payload).lower()
        
        for pattern in exploit_patterns:
            if pattern in payload_lower:
                return True, 0.9, f"Web exploit detected: {pattern} in {endpoint}"
        
        # Suspicious endpoints
        suspicious_endpoints = [
            '/admin/config', '/system/exec', '/cgi-bin/',
            '/.env', '/config.php', '/wp-admin'
        ]
        
        for suspicious in suspicious_endpoints:
            if suspicious in endpoint.lower():
                return True, 0.75, f"Suspicious endpoint access: {endpoint}"
        
        return False, 0.0, "Normal request"


# Global instances
_attack_detector = None
_network_attack_detector = None

def get_attack_detector():
    """Get attack detector instance"""
    global _attack_detector
    if _attack_detector is None:
        _attack_detector = AttackDetector()
    return _attack_detector

def get_network_attack_detector():
    """Get network attack detector instance"""
    global _network_attack_detector
    if _network_attack_detector is None:
        _network_attack_detector = NetworkAttackDetector()
    return _network_attack_detector

