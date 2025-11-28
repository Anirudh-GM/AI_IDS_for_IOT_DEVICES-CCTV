# CCTV Attack Testing Guide

## Overview
This guide shows how to test the AI-IDS intrusion detection system by simulating various attack scenarios from another terminal.

## Prerequisites
- AI-IDS system running on target machine (port 5000)
- Python 3 with requests library installed
- Network access to target system

## Quick Start

### 1. Basic Attack Test
```bash
# Install requests if needed
pip install requests

# Run quick attack
python quick_attack.py

# Or specify target IP
python quick_attack.py http://192.168.1.100:5000
```

### 2. Advanced Attack Scenarios
```bash
# Basic manual attack
python attack_simulation.py http://localhost:5000 basic

# Video injection attack
python attack_simulation.py http://localhost:5000 injection

# Burst attacks (multiple rapid attacks)
python attack_simulation.py http://localhost:5000 burst

# Mixed attack patterns
python attack_simulation.py http://localhost:5000 mixed

# Stealth attacks (slower, harder to detect)
python attack_simulation.py http://localhost:5000 stealth
```

## Attack Scenarios

### 1. Manual Attack Simulation
- **Purpose**: Tests manual intrusion detection
- **Duration**: 10 seconds
- **Expected**: Session-based logging with "MANUAL_ATTACK_SESSION"

### 2. Video Injection Attack
- **Purpose**: Tests video feed manipulation detection
- **Duration**: 10 seconds  
- **Expected**: Session-based logging with "INJECT_ATTACK_SESSION"

### 3. Burst Attack Pattern
- **Purpose**: Tests system under rapid attack sequences
- **Pattern**: 5 attacks alternating between manual/inject
- **Expected**: Multiple session logs with timing analysis

### 4. Mixed Attack Scenario
- **Purpose**: Complex attack pattern testing
- **Pattern**: Manual → Inject → Burst sequence
- **Expected**: Comprehensive detection across attack types

### 5. Stealth Attack Pattern
- **Purpose**: Tests detection of subtle, spaced attacks
- **Pattern**: Short attacks with long delays
- **Expected**: Individual session detection

## What to Monitor

### 1. AI-IDS Dashboard
Open `http://localhost:5000` in your browser and watch:

#### Event Logs Tab
- **Session Logs**: Look for `MANUAL_ATTACK_SESSION` and `INJECT_ATTACK_SESSION`
- **Timestamps**: Verify accurate attack timing
- **Duration**: Check session duration calculations
- **Expand Details**: Click sessions to see detailed information

#### Analytics Tab
- **Security Score**: Should decrease during attacks
- **Event Charts**: Pie chart should show attack distribution
- **Timeline**: Visual attack timeline
- **Statistics**: Total events and breakdown

#### Monitoring Tab
- **Live Feed**: Should show "ALERT" status during attacks
- **Status Indicators**: Camera status and alert count
- **Control Buttons**: Can manually trigger attacks from UI

### 2. System Logs
In the terminal running the AI-IDS system, watch for:
```
2025-11-28 13:45:00,123 - INFO - Manual attack started
2025-11-28 13:45:10,456 - INFO - Manual attack: 13:45:00 - 13:45:10 (10.2s)
```

### 3. Recordings Tab
- **Video Evidence**: Check recordings during attack periods
- **Timestamp Overlays**: Verify timestamps on recorded video
- **Download**: Export recordings for analysis

## Expected Detection Results

### Manual Attack Detection
```
Event Type: MANUAL_ATTACK_SESSION
Reason: Manual attack: 13:45:00 - 13:45:10 (10.2s)
Session Data:
  - Attack Type: Manual
  - Duration: 10.2s
  - Start Time: 13:45:00
  - End Time: 13:45:10
```

### Injection Attack Detection
```
Event Type: INJECT_ATTACK_SESSION  
Reason: Inject attack: 13:45:15 - 13:45:25 (10.1s)
Session Data:
  - Attack Type: Inject
  - Duration: 10.1s  
  - Start Time: 13:45:15
  - End Time: 13:45:25
```

## Testing Checklist

### Before Attack
- [ ] AI-IDS system is running
- [ ] Camera is connected and streaming
- [ ] Detection is enabled
- [ ] Event logs are empty or baseline established
- [ ] Security score is at normal level

### During Attack
- [ ] Alert status appears in monitoring tab
- [ ] Video feed shows attack overlay
- [ ] Event logs populate in real-time
- [ ] Security score decreases
- [ ] Charts update with attack data

### After Attack
- [ ] Session logs created for each attack
- [ ] Attack duration calculated correctly
- [ ] Security score recovers
- [ ] Video recordings captured during attack
- [ ] Analytics show attack statistics

## Advanced Testing

### 1. Network Attack Testing
```bash
# Test from different network segments
python attack_simulation.py http://192.168.1.100:5000 burst

# Test with different target ports
python attack_simulation.py http://192.168.1.100:8080 basic
```

### 2. Concurrent Attack Testing
```bash
# Run multiple attack scripts simultaneously
# Terminal 1:
python attack_simulation.py http://localhost:5000 mixed

# Terminal 2:  
python quick_attack.py http://localhost:5000
```

### 3. Stress Testing
```bash
# Continuous attack loop
while true; do
    python quick_attack.py http://localhost:5000
    sleep 5
done
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```
❌ Cannot connect to target system: [Errno 61] Connection refused
```
**Solution**: Check if AI-IDS is running and firewall settings

#### 2. Attack Not Triggering
```
❌ Failed to trigger manual attack: 500
```
**Solution**: Check if detection is enabled in the system

#### 3. No Detection Events
**Solution**: 
- Verify detection is enabled
- Check camera is connected
- Refresh the dashboard

#### 4. Session Logs Not Appearing
**Solution**:
- Wait a few seconds after attack stops
- Check browser console for errors
- Verify API endpoints are responding

## Security Considerations

### Authorized Testing Only
- Only test systems you own or have permission to test
- Use in isolated network environments
- Don't test production systems without authorization

### Network Safety
- Use local network (192.168.x.x) when possible
- Avoid public internet testing
- Monitor network traffic during tests

## Performance Monitoring

During attack testing, monitor:
- CPU usage on target system
- Memory consumption
- Network bandwidth
- Disk space (recordings)
- Response times

## Success Criteria

The AI-IDS system should successfully:
1. ✅ Detect all attack types within 2 seconds
2. ✅ Log session-based attack summaries
3. ✅ Update analytics in real-time
4. ✅ Maintain video recording during attacks
5. ✅ Recover security score after attacks
6. ✅ Generate accurate timestamps
7. ✅ Handle multiple concurrent attacks

## Next Steps

After successful testing:
1. Review detection accuracy
2. Analyze session timing precision
3. Check video recording quality during attacks
4. Verify analytics calculations
5. Test additional attack patterns
6. Document any false positives/negatives
