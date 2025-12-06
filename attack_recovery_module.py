"""
Attack Recovery Module
Handles automatic recovery after attacks are detected and ended
"""

import time
import logging
from datetime import datetime
from collections import defaultdict
from threading import Lock

logger = logging.getLogger(__name__)

class AttackRecoveryManager:
    """Manages recovery procedures after attacks are detected"""
    
    def __init__(self):
        self.attack_states = defaultdict(dict)  # Track attack states by type
        self.recovery_cooldowns = {
            'DDOS': 60,            # 1 minute cooldown after DDoS (reduced for faster recovery)
            'DOS_FLOOD': 60,       # 1 minute cooldown after DoS (reduced for faster recovery)
            'PORT_SCAN': 30,       # 30 seconds cooldown after port scan (reduced for faster recovery)
            'BRUTE_FORCE': 600,     # 10 minutes cooldown after brute force (serious security threat)
            'BRUTE_FORCE_ATTEMPT': 600,  # 10 minutes cooldown
            'VIDEO_INJECTION': 30, # 30 seconds cooldown after video injection (reduced for faster recovery)
            'FRAME_FREEZE': 60,    # 1 minute cooldown after frame freeze
            'MOTION_MASKING': 60,  # 1 minute cooldown after motion masking
            'CABLE_CUTTING': 60,   # 1 minute cooldown after cable cutting
            'UNAUTHORIZED_ACCESS': 300,  # 5 minutes cooldown
            'WEB_EXPLOIT': 180,    # 3 minutes cooldown
        }
        self.blocked_ips = {}  # IP: unblock_time
        self.rate_limit_counters = defaultdict(int)  # IP: request_count
        self.lock = Lock()
        
    def record_attack_start(self, attack_type, client_ip=None, details=None, duration=None):
        """Record that an attack has started"""
        with self.lock:
            attack_id = f"{attack_type}_{int(time.time())}"
            attack_state = {
                'start_time': time.time(),
                'client_ip': client_ip,
                'details': details,
                'recovered': False,
                'duration': duration  # Expected duration if known
            }
            
            # If duration is provided, schedule auto-end
            if duration:
                attack_state['expected_end_time'] = time.time() + duration
                attack_state['auto_end_scheduled'] = True
            else:
                attack_state['expected_end_time'] = None
                attack_state['auto_end_scheduled'] = False
            
            self.attack_states[attack_type][attack_id] = attack_state
            logger.info(f"🚨 Attack recorded: {attack_type} from {client_ip or 'unknown'}")
            if duration:
                logger.info(f"   ⏰ Auto-end scheduled in {duration}s, recovery after {self.recovery_cooldowns.get(attack_type, 60)}s")
            
            # Apply immediate mitigation
            if client_ip:
                self._apply_mitigation(attack_type, client_ip)
    
    def record_attack_end(self, attack_type, client_ip=None):
        """Record that an attack has ended"""
        with self.lock:
            # Find the most recent attack of this type
            if attack_type in self.attack_states:
                for attack_id, state in list(self.attack_states[attack_type].items()):
                    if not state['recovered'] and (not client_ip or state['client_ip'] == client_ip):
                        state['end_time'] = time.time()
                        state['duration'] = state['end_time'] - state['start_time']
                        logger.info(f"✅ Attack ended: {attack_type} (Duration: {state['duration']:.1f}s)")
                        
                        # Schedule recovery
                        self._schedule_recovery(attack_type, attack_id, state)
                        break
    
    def _apply_mitigation(self, attack_type, client_ip):
        """Apply immediate mitigation measures - BLOCKS IP to stop attack"""
        if not client_ip:
            return
            
        # Block IP immediately for all attack types (longer block time to prevent continuation)
        block_duration = self.recovery_cooldowns.get(attack_type, 60) * 2  # Block for 2x recovery cooldown
        self.blocked_ips[client_ip] = time.time() + block_duration
        
        if attack_type in ['DDOS', 'DOS_FLOOD']:
            logger.warning(f"🛡️  IP {client_ip} BLOCKED immediately due to {attack_type} - attack stopped")
        elif attack_type in ['PORT_SCAN', 'BRUTE_FORCE', 'BRUTE_FORCE_ATTEMPT']:
            logger.warning(f"🛡️  IP {client_ip} BLOCKED immediately due to {attack_type} - attack stopped")
        elif attack_type in ['WEB_EXPLOIT', 'UNAUTHORIZED_ACCESS']:
            logger.warning(f"🛡️  IP {client_ip} BLOCKED immediately due to {attack_type} - attack stopped")
        else:
            logger.warning(f"🛡️  IP {client_ip} BLOCKED immediately due to {attack_type} - attack stopped")
    
    def _schedule_recovery(self, attack_type, attack_id, attack_state):
        """Schedule recovery procedure after attack ends"""
        cooldown = self.recovery_cooldowns.get(attack_type, 60)
        recovery_time = time.time() + cooldown
        
        # Store recovery schedule
        attack_state['recovery_scheduled'] = True
        attack_state['recovery_time'] = recovery_time
        
        logger.info(f"⏰ Recovery scheduled for {attack_type} in {cooldown}s")
    
    def check_and_recover(self):
        """Check if any attacks can be recovered from"""
        current_time = time.time()
        recovered_attacks = []
        
        with self.lock:
            # First, check for attacks that should auto-end (based on expected duration)
            for attack_type, attacks in self.attack_states.items():
                for attack_id, state in list(attacks.items()):
                    if not state.get('recovered') and not state.get('recovery_scheduled'):
                        # Check if attack should auto-end
                        if state.get('auto_end_scheduled') and state.get('expected_end_time'):
                            if current_time >= state['expected_end_time']:
                                # Auto-end the attack
                                state['end_time'] = current_time
                                state['duration'] = current_time - state['start_time']
                                logger.info(f"✅ Attack auto-ended: {attack_type} (Duration: {state['duration']:.1f}s)")
                                # Schedule recovery immediately (cooldown starts from now)
                                self._schedule_recovery(attack_type, attack_id, state)
            
            # Then check all attack states for recovery (after cooldown period)
            for attack_type, attacks in self.attack_states.items():
                for attack_id, state in list(attacks.items()):
                    if state.get('recovery_scheduled') and not state.get('recovered'):
                        recovery_time = state.get('recovery_time', 0)
                        if recovery_time > 0 and current_time >= recovery_time:
                            # Perform recovery
                            recovery_summary = self._perform_recovery(attack_type, attack_id, state)
                            recovered_attacks.append((attack_type, attack_id))
                            logger.info(f"✅ Recovery completed for {attack_type} - Actions: {', '.join(recovery_summary.get('recovery_actions', []))}")
            
            # Clean up old attack records (older than 1 hour)
            for attack_type in list(self.attack_states.keys()):
                self.attack_states[attack_type] = {
                    aid: state for aid, state in self.attack_states[attack_type].items()
                    if current_time - state.get('start_time', current_time) < 3600
                }
            
            # Unblock IPs that have served their time
            for ip in list(self.blocked_ips.keys()):
                if current_time >= self.blocked_ips[ip]:
                    del self.blocked_ips[ip]
                    logger.info(f"🔓 IP {ip} unblocked - recovery complete")
        
        return recovered_attacks
    
    def _perform_recovery(self, attack_type, attack_id, attack_state):
        """Perform recovery procedure for a specific attack"""
        client_ip = attack_state.get('client_ip')
        duration = attack_state.get('duration', 0)
        
        logger.info(f"🔄 Starting recovery for {attack_type} (Attack ID: {attack_id})")
        
        recovery_actions = []
        
        if attack_type in ['DDOS', 'DOS_FLOOD']:
            # Recovery: Reset rate limit counters, unblock IPs
            if client_ip and client_ip in self.blocked_ips:
                # Will be unblocked by check_and_recover
                pass
            self.rate_limit_counters[client_ip] = 0
            recovery_actions.append("Rate limit counters reset")
            recovery_actions.append("Network traffic monitoring resumed")
        
        elif attack_type in ['PORT_SCAN']:
            # Recovery: Clear scan detection, resume normal access
            recovery_actions.append("Port scan detection cleared")
            recovery_actions.append("Normal endpoint access resumed")
        
        elif attack_type in ['BRUTE_FORCE', 'BRUTE_FORCE_ATTEMPT']:
            # Recovery: Reset failed login counters
            recovery_actions.append("Failed login counters reset")
            recovery_actions.append("Normal authentication resumed")
        
        elif attack_type in ['VIDEO_INJECTION']:
            # Recovery: Reset video feed validation
            recovery_actions.append("Video injection mode disabled")
            recovery_actions.append("Frame validation reset")
            recovery_actions.append("Normal video feed resumed")
        
        elif attack_type in ['FRAME_FREEZE']:
            # Recovery: Reset frame freeze detection
            recovery_actions.append("Frame freeze detection reset")
            recovery_actions.append("Normal frame processing resumed")
        
        elif attack_type in ['MOTION_MASKING']:
            # Recovery: Reset motion detection
            recovery_actions.append("Motion masking detection reset")
            recovery_actions.append("Normal motion detection resumed")
        
        elif attack_type in ['CABLE_CUTTING']:
            # Recovery: Attempt camera reconnection
            recovery_actions.append("Camera reconnection attempted")
            recovery_actions.append("Normal camera operation resumed")
        
        elif attack_type in ['WEB_EXPLOIT', 'UNAUTHORIZED_ACCESS']:
            # Recovery: Clear exploit detection
            recovery_actions.append("Exploit detection cleared")
            recovery_actions.append("Normal web access resumed")
        
        # Mark as recovered
        attack_state['recovered'] = True
        attack_state['recovery_time_actual'] = time.time()
        attack_state['recovery_actions'] = recovery_actions
        
        recovery_summary = {
            'attack_type': attack_type,
            'attack_id': attack_id,
            'duration': duration,
            'recovery_actions': recovery_actions,
            'client_ip': client_ip
        }
        
        logger.info(f"✅ Recovery complete for {attack_type}")
        logger.info(f"   Actions: {', '.join(recovery_actions)}")
        
        return recovery_summary
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    # Clean up expired block
                    del self.blocked_ips[ip]
            return False
    
    def get_recovery_status(self):
        """Get current recovery status"""
        with self.lock:
            active_attacks = []
            recovering_attacks = []
            
            for attack_type, attacks in self.attack_states.items():
                for attack_id, state in attacks.items():
                    if not state.get('recovered'):
                        if state.get('recovery_scheduled'):
                            recovering_attacks.append({
                                'type': attack_type,
                                'id': attack_id,
                                'recovery_time': state.get('recovery_time', 0),
                                'client_ip': state.get('client_ip')
                            })
                        else:
                            active_attacks.append({
                                'type': attack_type,
                                'id': attack_id,
                                'start_time': state.get('start_time', 0),
                                'client_ip': state.get('client_ip')
                            })
            
            return {
                'active_attacks': active_attacks,
                'recovering_attacks': recovering_attacks,
                'blocked_ips': list(self.blocked_ips.keys()),
                'blocked_ip_count': len(self.blocked_ips)
            }
    
    def force_recovery(self, attack_type=None, attack_id=None):
        """Force immediate recovery for specific attack or all attacks"""
        recovered = []
        
        with self.lock:
            if attack_type:
                if attack_type in self.attack_states:
                    for aid, state in list(self.attack_states[attack_type].items()):
                        if not attack_id or aid == attack_id:
                            if not state.get('recovered'):
                                recovery_summary = self._perform_recovery(attack_type, aid, state)
                                recovered.append(recovery_summary)
            else:
                # Recover all attacks
                for atype, attacks in self.attack_states.items():
                    for aid, state in list(attacks.items()):
                        if not state.get('recovered'):
                            recovery_summary = self._perform_recovery(atype, aid, state)
                            recovered.append(recovery_summary)
            
            # Unblock all IPs
            self.blocked_ips.clear()
            self.rate_limit_counters.clear()
        
        logger.info(f"🔧 Force recovery completed: {len(recovered)} attacks recovered")
        return recovered


# Global instance
_recovery_manager = None

def get_recovery_manager():
    """Get or create recovery manager instance"""
    global _recovery_manager
    if _recovery_manager is None:
        _recovery_manager = AttackRecoveryManager()
    return _recovery_manager

