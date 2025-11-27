# realtime_video_ids.py
# Stateful IDS that triggers a sustained-obstruction alert after N seconds.
import cv2
import numpy as np
import time

class IDSState:
    def __init__(self,
                 obstruction_seconds=12,
                 motion_diff_threshold=2500,
                 brightness_low=25,
                 cooldown_seconds=300):
        """
        obstruction_seconds: seconds of continuous dark+no-motion to alert
        motion_diff_threshold: pixel count threshold to consider there is motion
        brightness_low: below this mean brightness consider 'dark/covered'
        cooldown_seconds: ignore new alerts for this many seconds after an alert
        """
        self.obstruction_seconds = obstruction_seconds
        self.motion_diff_threshold = motion_diff_threshold
        self.brightness_low = brightness_low
        self.cooldown_seconds = cooldown_seconds

        self._prev_gray = None
        self._obstruction_start = None
        self._last_alert_ts = 0

    def reset(self):
        self._prev_gray = None
        self._obstruction_start = None
        self._last_alert_ts = 0

    def process_frame(self, frame):
        """
        Input: BGR frame
        Returns: annotated_frame (BGR), alert_bool, alert_reason (str or None)
        """
        now = time.time()

        # If in cooldown, annotate and return no alert
        if now - self._last_alert_ts < self.cooldown_seconds:
            remaining = int(self.cooldown_seconds - (now - self._last_alert_ts))
            return self._annotate(frame, note=f"Cooldown {remaining}s"), False, None

        # downscale for speed
        h, w = frame.shape[:2]
        small = cv2.resize(frame, (max(160, int(w*0.5)), max(120, int(h*0.5))))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        gray_blur = cv2.GaussianBlur(gray, (5,5), 0)

        mean_brightness = float(np.mean(gray_blur))

        # initialize previous
        if self._prev_gray is None:
            self._prev_gray = gray_blur.copy()
            return self._annotate(frame, note="Initializing IDS..."), False, None

        diff = cv2.absdiff(self._prev_gray, gray_blur)
        motion_pixels = int(np.sum(diff > 25))

        is_dark = mean_brightness < self.brightness_low
        is_no_motion = motion_pixels < self.motion_diff_threshold

        # If conditions for obstruction are met, start timing
        if is_dark and is_no_motion:
            if self._obstruction_start is None:
                self._obstruction_start = now
            elapsed = now - self._obstruction_start
            if elapsed >= self.obstruction_seconds:
                # Fire alert and set cooldown timestamp
                self._last_alert_ts = now
                return self._annotate(frame, alert=True, reason="Sustained obstruction", brightness=int(mean_brightness), motion=motion_pixels), True, "Sustained obstruction"
            else:
                return self._annotate(frame, note=f"Cover candidate: {int(elapsed)}s/{self.obstruction_seconds}s", brightness=int(mean_brightness), motion=motion_pixels), False, None
        else:
            # Clear obstruction timer
            self._obstruction_start = None

        self._prev_gray = gray_blur.copy()
        return self._annotate(frame, note="OK", brightness=int(mean_brightness), motion=motion_pixels), False, None

    def _annotate(self, frame, alert=False, reason=None, note=None, brightness=None, motion=None):
        out = frame.copy()
        h, w = out.shape[:2]
        # draw status bar
        cv2.rectangle(out, (0,0), (w, 36), (0,0,0), -1)
        status = "ALERT" if alert else "OK"
        color = (0,0,255) if alert else (0,255,0)
        cv2.putText(out, f"Status: {status}", (10,24), cv2.FONT_HERSHEY_SIMPLEX, 0.75, color, 2)
        y = 28
        if reason:
            cv2.putText(out, f"Reason: {reason}", (150,24), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 1)
        if note:
            cv2.putText(out, str(note), (10, h-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200,200,200), 1)
        if brightness is not None:
            cv2.putText(out, f"B:{brightness}", (w-150,24), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200,200,200), 1)
        if motion is not None:
            cv2.putText(out, f"M:{motion}", (w-90,24), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (200,200,200), 1)
        return out
