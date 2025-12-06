# Real Attack Simulation Guide

## Overview

Run attacks from a **separate terminal** like a real attacker would. This simulates actual malicious traffic that your AI-IDS will detect in real-time.

## Quick Start

### 1. Start Your AI-IDS Server
```bash
# Terminal 1: Start the Flask server
python app.py
```

### 2. Run Attack from Separate Terminal
```bash
# Terminal 2: Run attack simulation (menu-driven)
python real_attack_simulator.py
```

## Available Attacks

### Major Attack Types

#### 1. DDoS Flood Attack
- Sends rapid requests to overwhelm server
- Rate: 25 requests/second (adjustable)
- Duration: 30 seconds (adjustable)

#### 2. Port Scan Attack
- Rapidly scans multiple endpoints
- Maps system structure
- Identifies available services

#### 3. Brute Force Attack
- Multiple failed login attempts
- Tries common passwords
- Simulates unauthorized access attempts

#### 4. Video Injection Attack
- Enables video injection mode
- System detects frame freeze/injection
- Real-time detection by AI-IDS

## Usage

Simply run the script and select from the interactive menu:
```bash
python real_attack_simulator.py
```

Then choose:
- **1** for DDoS Flood Attack
- **2** for Port Scan Attack
- **3** for Brute Force Attack
- **4** for Video Injection Attack
- **5** to Change Target URL
- **0** to Exit

## What Happens

### 1. Attack Starts
- Script connects to target server
- Begins sending malicious traffic
- Real-time output shows attack progress

### 2. AI-IDS Detection
- System analyzes traffic in real-time
- ML models classify as attack
- Logs created automatically

### 3. Dashboard Updates
- Logs appear in dashboard
- Real-time detection shown
- Email alerts sent (if configured)

## Attack Details

### DDoS Flood
- **Traffic**: Rapid GET requests to multiple endpoints
- **Pattern**: Burst requests at specified rate
- **Detection**: High request rate triggers DoS detection

### Port Scan
- **Traffic**: Sequential requests to 30+ endpoints
- **Pattern**: Rapid scanning with short delays
- **Detection**: Multiple endpoints accessed quickly

### Brute Force
- **Traffic**: POST requests with common passwords
- **Pattern**: Repeated login attempts
- **Detection**: Failed login attempt tracking

### Video Injection
- **Action**: Enables video injection mode
- **Pattern**: Frame freeze/injection
- **Detection**: Frame analysis detects injection

## Tips

1. **Run from Separate Terminal**: 
   - Keep server running in Terminal 1
   - Run attacks from Terminal 2

2. **Watch Dashboard**:
   - Open dashboard in browser
   - Go to Event Logs tab
   - Watch attacks appear in real-time

3. **Check Terminal Output**:
   - Server terminal shows detection logs
   - Attack terminal shows attack progress

4. **Multiple Attacks**:
   - Run different attacks sequentially
   - Or run multiple terminals simultaneously

## Safety

- ✅ Attacks only target your local server
- ✅ No external systems affected
- ✅ Safe for testing and demonstration
- ✅ All traffic is logged

---

**Usage**: Run attacks from separate terminal like a real attacker! 🚨
