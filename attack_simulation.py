#!/usr/bin/env python3
"""
CCTV Attack Simulation Scripts
Test the AI-IDS intrusion detection system with various attack scenarios
"""

import requests
import time
import threading
import json
import sys
from datetime import datetime

class CCTVAttacker:
    def __init__(self, target_url="http://localhost:5000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.attacks_running = False
        
    def check_system_status(self):
        """Check if the target system is running"""
        try:
            response = self.session.get(f"{self.target_url}/api/status", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Target system online at {self.target_url}")
                print(f"📹 Camera Status: {'Online' if data['camera_connected'] else 'Offline'}")
                print(f"🔍 Detection Status: {'Active' if data['detection_enabled'] else 'Inactive'}")
                return True
            else:
                print(f"❌ Target system responded with status {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to target system: {e}")
            return False
    
    def trigger_manual_attack(self, duration=10):
        """Trigger manual attack simulation"""
        print(f"\n🚨 Starting Manual Attack Simulation ({duration}s)...")
        try:
            # Start manual attack
            response = self.session.post(f"{self.target_url}/api/control", 
                                       json={"action": "toggle_manual"})
            if response.status_code == 200:
                print("✅ Manual attack triggered successfully")
                print(f"⏱️  Attack will run for {duration} seconds...")
                
                # Wait for specified duration
                time.sleep(duration)
                
                # Stop manual attack
                stop_response = self.session.post(f"{self.target_url}/api/control", 
                                                json={"action": "toggle_manual"})
                if stop_response.status_code == 200:
                    print("✅ Manual attack stopped")
                else:
                    print(f"❌ Failed to stop manual attack: {stop_response.status_code}")
            else:
                print(f"❌ Failed to trigger manual attack: {response.status_code}")
        except Exception as e:
            print(f"❌ Manual attack failed: {e}")
    
    def trigger_inject_attack(self, duration=10):
        """Trigger video injection attack simulation"""
        print(f"\n💻 Starting Video Injection Attack Simulation ({duration}s)...")
        try:
            # Start inject attack
            response = self.session.post(f"{self.target_url}/api/control", 
                                       json={"action": "toggle_inject"})
            if response.status_code == 200:
                print("✅ Video injection attack triggered successfully")
                print(f"⏱️  Attack will run for {duration} seconds...")
                
                # Wait for specified duration
                time.sleep(duration)
                
                # Stop inject attack
                stop_response = self.session.post(f"{self.target_url}/api/control", 
                                                json={"action": "toggle_inject"})
                if stop_response.status_code == 200:
                    print("✅ Video injection attack stopped")
                else:
                    print(f"❌ Failed to stop inject attack: {stop_response.status_code}")
            else:
                print(f"❌ Failed to trigger inject attack: {response.status_code}")
        except Exception as e:
            print(f"❌ Video injection attack failed: {e}")
    
    def continuous_attack_burst(self, attacks=5, interval=3):
        """Launch multiple attacks in quick succession"""
        print(f"\n🔥 Starting Continuous Attack Burst ({attacks} attacks, {interval}s interval)...")
        
        for i in range(attacks):
            print(f"\n📍 Attack {i+1}/{attacks}")
            
            # Alternate between manual and inject attacks
            if i % 2 == 0:
                self.trigger_manual_attack(2)
            else:
                self.trigger_inject_attack(2)
            
            if i < attacks - 1:
                print(f"⏳ Waiting {interval} seconds before next attack...")
                time.sleep(interval)
        
        print("✅ Continuous attack burst completed")
    
    def stop_detection(self):
        """Attempt to stop detection (privilege escalation test)"""
        print("\n🛑 Attempting to Stop Detection...")
        try:
            response = self.session.post(f"{self.target_url}/api/control", 
                                       json={"action": "stop"})
            if response.status_code == 200:
                print("⚠️  Detection stopped - this indicates a security vulnerability!")
            else:
                print(f"❌ Failed to stop detection: {response.status_code}")
        except Exception as e:
            print(f"❌ Stop detection failed: {e}")
    
    def monitor_system_logs(self, duration=30):
        """Monitor system logs during attack"""
        print(f"\n📊 Monitoring System Logs for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                response = self.session.get(f"{self.target_url}/api/status", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    logs = data.get('log', [])
                    
                    # Show recent logs
                    recent_logs = [log for log in logs if 
                                  time.time() - time.mktime(datetime.strptime(
                                      log['time'], "%Y-%m-%d %H:%M:%S").timetuple()) < 30]
                    
                    if recent_logs:
                        print(f"\n📋 Recent Events ({len(recent_logs)}):")
                        for log in recent_logs[-5:]:  # Show last 5 events
                            print(f"  {log['time']} - {log['event_type']}: {log['reason']}")
                
                time.sleep(5)
            except Exception as e:
                print(f"❌ Log monitoring error: {e}")
                break
    
    def run_attack_scenario(self, scenario="basic"):
        """Run predefined attack scenarios"""
        scenarios = {
            "basic": lambda: self.trigger_manual_attack(10),
            "injection": lambda: self.trigger_inject_attack(10),
            "burst": lambda: self.continuous_attack_burst(5, 2),
            "mixed": lambda: [
                self.trigger_manual_attack(5),
                time.sleep(2),
                self.trigger_inject_attack(5),
                time.sleep(2),
                self.continuous_attack_burst(3, 1)
            ],
            "stealth": lambda: [
                self.trigger_manual_attack(2),
                time.sleep(10),
                self.trigger_inject_attack(2),
                time.sleep(15),
                self.trigger_manual_attack(3)
            ]
        }
        
        if scenario not in scenarios:
            print(f"❌ Unknown scenario: {scenario}")
            print(f"Available scenarios: {list(scenarios.keys())}")
            return
        
        print(f"\n🎯 Running Attack Scenario: {scenario.upper()}")
        print("="*50)
        
        # Start monitoring in background
        monitor_thread = threading.Thread(target=self.monitor_system_logs, args=(60,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Execute scenario
        scenario_func = scenarios[scenario]
        if callable(scenario_func):
            scenario_func()
        else:
            # It's a list of actions
            for action in scenario_func:
                if callable(action):
                    action()
                else:
                    time.sleep(action)
        
        print(f"\n✅ Scenario '{scenario}' completed")
        print("📊 Check the AI-IDS dashboard for detection results")

def main():
    print("🎯 CCTV Attack Simulation Tool")
    print("="*50)
    
    if len(sys.argv) < 2:
        print("Usage: python attack_simulation.py <target_url> [scenario]")
        print("Scenarios: basic, injection, burst, mixed, stealth")
        print("Example: python attack_simulation.py http://192.168.1.100:5000 basic")
        return
    
    target_url = sys.argv[1]
    scenario = sys.argv[2] if len(sys.argv) > 2 else "basic"
    
    attacker = CCTVAttacker(target_url)
    
    # Check if target is online
    if not attacker.check_system_status():
        return
    
    print(f"\n🎯 Target: {target_url}")
    print(f"📋 Scenario: {scenario}")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run the attack scenario
    attacker.run_attack_scenario(scenario)
    
    print(f"\n⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n🔍 Check the AI-IDS dashboard for:")
    print("  • Event logs showing attack detection")
    print("  • Session-based attack summaries")
    print("  • Security score changes")
    print("  • Recording timestamps during attacks")

if __name__ == "__main__":
    main()
