import cv2
import time
import pygame
import random
from datetime import datetime
import sqlite3

# Initialize Pygame Mixer
pygame.mixer.init()

# Use the fixed WAV file
ALERT_SOUND = "alert_fixed.wav"

# Database connection
conn = sqlite3.connect("intrusion_logs.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS intrusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    device TEXT,
    attack_type TEXT
)
""")
conn.commit()

# Simulated IoT devices and attacks
devices = ["Camera", "Router", "Smart Light", "Thermostat"]
attacks = ["Port Scan", "Malware Injection", "Data Breach"]

print("🔍 Real-time AI-based Intrusion Detection started...\n")

try:
    cap = cv2.VideoCapture(0)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Simulate random intrusion event
        if random.random() < 0.3:
            device = random.choice(devices)
            attack = random.choice(attacks)
            timestamp = datetime.now().strftime("[%H:%M:%S]")
            print(f"{timestamp} {device} → {attack}")

            try:
                sound = pygame.mixer.Sound(ALERT_SOUND)
                sound.play()
            except Exception as e:
                print(f"⚠️ Sound error: {e}")

            cursor.execute("INSERT INTO intrusions (timestamp, device, attack_type) VALUES (?, ?, ?)",
                           (timestamp, device, attack))
            conn.commit()
            print("✅ Logged in DB")

        # Display camera feed
        cv2.imshow("AI-Based IDS for IoT Devices", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("\n🛑 Intrusion Detection stopped manually.")
            break

except KeyboardInterrupt:
    print("\n🛑 Intrusion Detection stopped manually.")

finally:
    cap.release()
    cv2.destroyAllWindows()
    conn.close()
