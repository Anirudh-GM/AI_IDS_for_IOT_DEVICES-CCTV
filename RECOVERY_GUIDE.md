# Attack Recovery System Guide

## Overview

The AI-IDS system includes an automatic recovery mechanism that detects when attacks end and automatically restores normal operation. This guide explains how the recovery system works for the 4 major attack types.

## Supported Attack Types

### 1. DDoS Flood Attack
- **Detection**: High request rate from specific IP
- **Mitigation**: IP blocking, rate limiting
- **Recovery**: 
  - Reset rate limit counters
  - Unblock IPs after cooldown (5 minutes)
  - Resume normal network traffic monitoring
- **Cooldown**: 5 minutes

### 2. Port Scan / Reconnaissance
- **Detection**: Rapid scanning of multiple endpoints
- **Mitigation**: IP blocking
- **Recovery**:
  - Clear port scan detection counters
  - Unblock IPs after cooldown (3 minutes)
  - Resume normal endpoint access
- **Cooldown**: 3 minutes

### 3. Brute Force Attack
- **Detection**: Multiple failed login attempts
- **Mitigation**: IP blocking, account lockout
- **Recovery**:
  - Reset failed login counters
  - Unblock IPs after cooldown (10 minutes)
  - Resume normal authentication
- **Cooldown**: 10 minutes

### 4. Video Injection Attack
- **Detection**: Frame freeze/injection patterns
- **Mitigation**: Video feed validation
- **Recovery**:
  - Disable video injection mode
  - Reset frame validation
  - Resume normal video feed processing
- **Cooldown**: 2 minutes

## How Recovery Works

### Automatic Recovery Process

1. **Attack Detection**: System detects attack and records it
2. **Immediate Mitigation**: IP blocking, rate limiting applied
3. **Attack End Detection**: System detects when attack stops
4. **Cooldown Period**: System waits for cooldown period
5. **Recovery Actions**: Automatic recovery procedures executed
6. **Normal Operation Resumed**: System returns to normal state
7. **Email Notification**: Recovery completion email sent

### Recovery Timeline

```
Attack Detected → Mitigation Applied → Attack Ends → Cooldown Period → Recovery → Normal Operation
     ↓                    ↓                  ↓              ↓              ↓            ↓
  Log Event          Block IP          Record End      Wait Time    Reset Counters  Resume
  Send Email         Rate Limit       Schedule Recovery  (varies)   Unblock IPs    Send Email
```

## API Endpoints

### Get Recovery Status
```http
GET /api/recovery-status
```

**Response:**
```json
{
  "success": true,
  "recovery_status": {
    "active_attacks": [
      {
        "type": "PORT_SCAN",
        "id": "PORT_SCAN_1234567890",
        "start_time": 1234567890.0,
        "client_ip": "192.168.1.100"
      }
    ],
    "recovering_attacks": [
      {
        "type": "DDOS",
        "id": "DDOS_1234567890",
        "recovery_time": 1234568190.0,
        "client_ip": "192.168.1.100"
      }
    ],
    "blocked_ips": ["192.168.1.100"],
    "blocked_ip_count": 1
  }
}
```

### Force Recovery
```http
POST /api/recovery/force
Content-Type: application/json

{
  "attack_type": "PORT_SCAN",  // Optional: specific attack type
  "attack_id": "PORT_SCAN_1234567890"  // Optional: specific attack ID
}
```

**Response:**
```json
{
  "success": true,
  "recovered_attacks": 2,
  "details": [
    {
      "attack_type": "PORT_SCAN",
      "attack_id": "PORT_SCAN_1234567890",
      "duration": 30.5,
      "recovery_actions": [
        "Port scan detection cleared",
        "Normal endpoint access resumed"
      ],
      "client_ip": "192.168.1.100"
    }
  ]
}
```

## Recovery Actions by Attack Type

### DDoS Flood Recovery
- ✅ Rate limit counters reset
- ✅ Network traffic monitoring resumed
- ✅ IP unblocked after cooldown

### Port Scan Recovery
- ✅ Port scan detection cleared
- ✅ Normal endpoint access resumed
- ✅ IP unblocked after cooldown

### Brute Force Recovery
- ✅ Failed login counters reset
- ✅ Normal authentication resumed
- ✅ IP unblocked after cooldown

### Video Injection Recovery
- ✅ Video injection mode disabled
- ✅ Frame validation reset
- ✅ Normal video feed resumed

## Monitoring Recovery

### Dashboard
- Check `/api/recovery-status` endpoint
- View recovery logs in event log
- Monitor recovery email notifications

### Logs
Recovery events are logged with type `RECOVERY_COMPLETE`:
```
Event: RECOVERY_COMPLETE - System recovered from PORT_SCAN attack
```

### Email Notifications
Recovery completion triggers email notification:
- **Subject**: 🔔 AI-IDS RECOVERY_COMPLETE
- **Body**: Recovery details and actions taken

## Manual Recovery

If automatic recovery doesn't trigger, you can force recovery:

```bash
# Force recovery for all attacks
curl -X POST http://localhost:5000/api/recovery/force \
  -H "Content-Type: application/json" \
  -d '{}'

# Force recovery for specific attack type
curl -X POST http://localhost:5000/api/recovery/force \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "PORT_SCAN"}'
```

## Best Practices

1. **Monitor Recovery Status**: Regularly check `/api/recovery-status`
2. **Review Recovery Logs**: Check event logs for recovery events
3. **Verify Normal Operation**: Confirm system is functioning normally after recovery
4. **Investigate Persistent Attacks**: If attacks continue, investigate root cause
5. **Adjust Cooldown Periods**: Modify cooldown times in `attack_recovery_module.py` if needed

## Configuration

Recovery cooldown periods can be adjusted in `attack_recovery_module.py`:

```python
self.recovery_cooldowns = {
    'DDOS': 300,           # 5 minutes
    'PORT_SCAN': 180,     # 3 minutes
    'BRUTE_FORCE': 600,   # 10 minutes
    'VIDEO_INJECTION': 120, # 2 minutes
    # ... more attack types
}
```

## Troubleshooting

### Recovery Not Triggering
- Check if attack has actually ended
- Verify recovery manager is initialized
- Check logs for recovery manager errors

### IPs Not Unblocking
- Check cooldown period hasn't expired
- Verify recovery process completed
- Use force recovery if needed

### Normal Operation Not Resumed
- Check recovery actions were executed
- Verify system state after recovery
- Review recovery logs for errors

---

**Note**: Recovery system automatically handles attack mitigation and restoration. Manual intervention is rarely needed.

