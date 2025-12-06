# How to Simulate Attacks - Step by Step Guide

## Overview

This guide shows you how to simulate the 4 major attack types using the menu-driven attack simulator. The simulator runs from a separate terminal and generates real attack traffic that your AI-IDS will detect.

## Prerequisites

1. **Start your AI-IDS server first** (Terminal 1)
2. **Run attack simulator** (Terminal 2 - separate terminal)

## Step-by-Step Instructions

### Step 1: Start the AI-IDS Server

Open **Terminal 1** and start your Flask server:

```bash
cd E:\BE\mini-project\AIOT-Guardian
python app.py
```

Wait for the server to start. You should see:
```
Starting Flask server...
Running on http://0.0.0.0:5000
```

**Keep this terminal running!**

### Step 2: Open a New Terminal for Attack Simulation

Open **Terminal 2** (a new terminal window):

```bash
cd E:\BE\mini-project\AIOT-Guardian
python real_attack_simulator.py
```

### Step 3: Use the Interactive Menu

You'll see a menu like this:

```
======================================================================
🚨 REAL ATTACK SIMULATOR - Interactive Menu
======================================================================

📡 MAJOR ATTACK TYPES:
   1. DDoS Flood Attack
   2. Port Scan / Reconnaissance
   3. Brute Force Attack
   4. Video Injection Attack

⚙️  OPTIONS:
   5. Change Target URL
   0. Exit
======================================================================

👉 Select attack (0-5):
```

### Step 4: Select an Attack Type

Type the number and press Enter:

#### Option 1: DDoS Flood Attack
```
👉 Select attack (0-5): 1

🚨 DDoS Flood Attack
   Duration (seconds) (default: 30): [Press Enter or type value]
   Request rate (req/s) (default: 25): [Press Enter or type value]
```

**What happens:**
- Sends rapid requests to overwhelm the server
- AI-IDS detects high request rate
- Email alert sent automatically
- System blocks the attacking IP
- Automatic recovery after 5 minutes

#### Option 2: Port Scan Attack
```
👉 Select attack (0-5): 2

🚨 Port Scan Attack
   Duration (seconds) (default: 20): [Press Enter or type value]
```

**What happens:**
- Rapidly scans multiple endpoints
- AI-IDS detects reconnaissance activity
- Email alert sent automatically
- System blocks the scanning IP
- Automatic recovery after 3 minutes

#### Option 3: Brute Force Attack
```
👉 Select attack (0-5): 3

🚨 Brute Force Attack
   Duration (seconds) (default: 30): [Press Enter or type value]
   Attempts per second (default: 3): [Press Enter or type value]
```

**What happens:**
- Multiple failed login attempts
- AI-IDS detects brute force pattern
- Email alert sent automatically
- System blocks the attacking IP
- Automatic recovery after 10 minutes

#### Option 4: Video Injection Attack
```
👉 Select attack (0-5): 4

🚨 Video Injection Attack
   Duration (seconds) (default: 20): [Press Enter or type value]
```

**What happens:**
- Enables video injection mode
- AI-IDS detects frame freeze/injection
- Email alert sent automatically
- System resets video validation
- Automatic recovery after 2 minutes

### Step 5: Watch the Results

#### In Terminal 2 (Attack Simulator):
You'll see attack progress:
```
🚨 [ATTACK] Starting DDoS Flood Attack
   Target: http://127.0.0.1:5000
   Duration: 30s, Rate: 25 req/s
   This will send 750 requests to overwhelm the server

✅ [ATTACK] DDoS Flood Complete: 742 requests sent
✅ Attack completed in 30.2 seconds
```

#### In Terminal 1 (Server):
You'll see detection logs:
```
🚨 AI-IDS Attack Detected: DOS_FLOOD from 127.0.0.1
🛡️  IP 127.0.0.1 blocked due to DOS_FLOOD
⏰ Recovery scheduled for DOS_FLOOD in 300s
✅ System recovered from DOS_FLOOD attack
```

#### In Dashboard:
1. Open browser: `http://localhost:5000`
2. Login to dashboard
3. Go to **Event Logs** tab
4. See attack detection in real-time:
   - Attack detected
   - IP blocked
   - Recovery scheduled
   - Recovery completed

#### Email Notifications:
- **Attack Detected Email**: Sent immediately when attack starts
- **Recovery Complete Email**: Sent when system recovers

### Step 6: Run Multiple Attacks

You can run multiple attacks sequentially:

1. Run DDoS attack (Option 1)
2. Wait for it to complete
3. Press Enter to return to menu
4. Run Port Scan attack (Option 2)
5. Repeat for other attack types

## Quick Examples

### Example 1: Quick DDoS Test
```bash
# Terminal 1: Start server
python app.py

# Terminal 2: Run simulator
python real_attack_simulator.py
# Select: 1 (DDoS)
# Duration: 10 (quick test)
# Rate: 20
```

### Example 2: Full Attack Sequence
```bash
# Terminal 1: Start server
python app.py

# Terminal 2: Run simulator
python real_attack_simulator.py
# Run all 4 attacks one by one:
# 1. DDoS (30s)
# 2. Port Scan (20s)
# 3. Brute Force (30s)
# 4. Video Injection (20s)
```

### Example 3: High-Intensity DDoS
```bash
# Terminal 2: Run simulator
python real_attack_simulator.py
# Select: 1 (DDoS)
# Duration: 60 (1 minute)
# Rate: 50 (high intensity)
```

## What to Observe

### During Attack:
1. ✅ Attack simulator shows progress
2. ✅ Server logs show detection
3. ✅ Dashboard shows attack in logs
4. ✅ Email alert received

### During Recovery:
1. ✅ Server logs show recovery process
2. ✅ Dashboard shows recovery complete
3. ✅ Email notification received
4. ✅ System resumes normal operation

## Troubleshooting

### Attack Not Detected?
- Check server is running (Terminal 1)
- Check target URL is correct (default: http://127.0.0.1:5000)
- Check server logs for errors
- Verify email is configured in `.env`

### Recovery Not Happening?
- Recovery is automatic (no action needed)
- Check server logs for recovery messages
- Recovery happens after cooldown period:
  - DDoS: 5 minutes
  - Port Scan: 3 minutes
  - Brute Force: 10 minutes
  - Video Injection: 2 minutes

### Email Not Received?
- Check `.env` file has correct Gmail credentials
- Check spam folder
- Verify email in `users.json` is correct
- Check server logs for email errors

## Attack Types Summary

| Attack | Duration | Detection | Recovery | Email |
|--------|----------|-----------|----------|-------|
| DDoS Flood | 30s default | Immediate | 5 min | ✅ |
| Port Scan | 20s default | Immediate | 3 min | ✅ |
| Brute Force | 30s default | Immediate | 10 min | ✅ |
| Video Injection | 20s default | Immediate | 2 min | ✅ |

## Tips

1. **Start with short durations** (10-20 seconds) for testing
2. **Watch both terminals** to see attack and detection
3. **Check dashboard logs** to see full attack timeline
4. **Monitor email** for automatic notifications
5. **Run attacks sequentially** to see recovery process

## Next Steps

After simulating attacks:
1. Review attack logs in dashboard
2. Check email notifications
3. Verify recovery completed
4. Test different attack intensities
5. Observe automatic recovery process

---

**Ready to test?** Start your server and run `python real_attack_simulator.py`! 🚨

