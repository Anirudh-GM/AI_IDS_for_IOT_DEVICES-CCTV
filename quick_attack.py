#!/usr/bin/env python3
"""
Quick Attack Script for Testing CCTV System
Simple script to trigger attacks on the AI-IDS system
"""

import requests
import time
import sys

def quick_attack(target_url="http://localhost:5000"):
    """Quick attack test"""
    print(f"🎯 Attacking CCTV System at {target_url}")
    print("="*40)
    
    try:
        # Check if system is online
        response = requests.get(f"{target_url}/api/status", timeout=5)
        if response.status_code != 200:
            print("❌ Target system not responding")
            return
        
        data = response.json()
        print(f"✅ System online - Camera: {'Connected' if data['camera_connected'] else 'Disconnected'}")
        
        # Trigger manual attack
        print("\n🚨 Triggering Manual Attack...")
        response = requests.post(f"{target_url}/api/control", 
                                json={"action": "toggle_manual"})
        
        if response.status_code == 200:
            print("✅ Manual attack started!")
            print("⏱️  Attack running for 10 seconds...")
            time.sleep(10)
            
            # Stop attack
            response = requests.post(f"{target_url}/api/control", 
                                    json={"action": "toggle_manual"})
            print("✅ Manual attack stopped")
        else:
            print(f"❌ Attack failed: {response.status_code}")
        
        # Wait a bit
        time.sleep(3)
        
        # Trigger injection attack
        print("\n💻 Triggering Video Injection Attack...")
        response = requests.post(f"{target_url}/api/control", 
                                json={"action": "toggle_inject"})
        
        if response.status_code == 200:
            print("✅ Injection attack started!")
            print("⏱️  Attack running for 10 seconds...")
            time.sleep(10)
            
            # Stop attack
            response = requests.post(f"{target_url}/api/control", 
                                    json={"action": "toggle_inject"})
            print("✅ Injection attack stopped")
        else:
            print(f"❌ Attack failed: {response.status_code}")
        
        print("\n🎉 Attack simulation completed!")
        print("🔍 Check the AI-IDS dashboard for detection results")
        
    except Exception as e:
        print(f"❌ Attack failed: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    quick_attack(target)
