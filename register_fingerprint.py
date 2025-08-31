#!/usr/bin/python3

import sys
import time
import os
import hashlib
from r503_fingerprint import FingerprintAuth

class FingerprintRegistration:
    def __init__(self):
        self.fp_auth = FingerprintAuth()
        self.mapping_file = "/etc/fido2_security_key/user_mappings.txt"
        self.ensure_directory()
        
    def ensure_directory(self):
        os.makedirs(os.path.dirname(self.mapping_file), exist_ok=True)
        
    def generate_user_id(self, username):
        hash_obj = hashlib.sha256(username.encode())
        return hash_obj.hexdigest()[:8].upper()
        
    def save_user_mapping(self, user_id, username):
        timestamp = int(time.time())
        mapping_line = f"{user_id}:{username}:{timestamp}\n"
        
        with open(self.mapping_file, "a") as f:
            f.write(mapping_line)
            
    def user_exists(self, username):
        try:
            with open(self.mapping_file, "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] == username:
                        return True
        except FileNotFoundError:
            pass
        return False
        
    def get_user_count(self):
        try:
            with open(self.mapping_file, "r") as f:
                return len([line for line in f if line.strip()])
        except FileNotFoundError:
            return 0
            
    def register_fingerprint(self, username):
        if self.user_exists(username):
            print(f"❌ User '{username}' already registered")
            return False
            
        if not self.fp_auth.initialize():
            print("❌ Could not initialize fingerprint sensor")
            return False
            
        try:
            current_count = self.fp_auth.get_enrolled_count()
            if current_count >= self.fp_auth.max_templates:
                print("❌ Sensor memory full")
                return False
                
            user_id = self.generate_user_id(username)
            numeric_id = int(user_id, 16) % self.fp_auth.max_templates
            
            print(f"📝 Registering: {username}")
            print(f"🆔 User ID: {user_id}")
            print(f"📍 Sensor slot: {numeric_id}")
            print()
            
            print("👆 Place your finger on the sensor (1st scan)...")
            time.sleep(2)
            
            if not self.fp_auth.sensor.get_image():
                print("❌ Failed to capture first image")
                return False
                
            if not self.fp_auth.sensor.image_to_template(1):
                print("❌ Failed to process first image")
                return False
                
            print("✅ First scan complete")
            print("🔄 Lift finger and place again (2nd scan)...")
            time.sleep(2)
            
            if not self.fp_auth.sensor.get_image():
                print("❌ Failed to capture second image")
                return False
                
            if not self.fp_auth.sensor.image_to_template(2):
                print("❌ Failed to process second image")
                return False
                
            print("✅ Second scan complete")
            print("🔄 Creating template...")
            
            if not self.fp_auth.sensor.create_template():
                print("❌ Failed to create template")
                return False
                
            print("💾 Storing template...")
            
            if not self.fp_auth.sensor.store_template(numeric_id, 1):
                print("❌ Failed to store template")
                return False
                
            self.save_user_mapping(user_id, username)
            print(f"✅ Registration successful for '{username}'")
            
            self.fp_auth.sensor.led_control(6, 0x80, 2, 5)
            return True
            
        except Exception as e:
            print(f"❌ Registration failed: {e}")
            return False
        finally:
            self.fp_auth.cleanup()
            
    def batch_register(self, usernames):
        successful = 0
        failed = 0
        
        for username in usernames:
            print(f"\n{'='*50}")
            print(f"Registering user {successful + failed + 1}/{len(usernames)}: {username}")
            print('='*50)
            
            if self.register_fingerprint(username):
                successful += 1
            else:
                failed += 1
                
            if successful + failed < len(usernames):
                input("\nPress Enter for next user...")
                
        print(f"\n📊 Registration Summary:")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📈 Total: {successful + failed}")
        
    def interactive_register(self):
        print("\n" + "=" * 50)
        print("    FIDO2 Security Key - Fingerprint Registration")
        print("=" * 50)
        
        current_count = 0
        if self.fp_auth.initialize():
            current_count = self.fp_auth.get_enrolled_count()
            self.fp_auth.cleanup()
            
        user_count = self.get_user_count()
        
        print(f"📊 Status:")
        print(f"   Enrolled templates: {current_count}/{self.fp_auth.max_templates}")
        print(f"   Registered users: {user_count}")
        print(f"   Available slots: {self.fp_auth.max_templates - current_count}")
        print()
        
        while True:
            username = input("👤 Enter username (or 'quit' to exit): ").strip()
            
            if username.lower() == 'quit':
                break
                
            if not username:
                print("❌ Username cannot be empty")
                continue
                
            if len(username) < 2:
                print("❌ Username must be at least 2 characters")
                continue
                
            if not username.replace('_', '').replace('-', '').isalnum():
                print("❌ Username can only contain letters, numbers, _ and -")
                continue
                
            self.register_fingerprint(username)
            
            another = input("\n🔄 Register another user? (y/N): ").strip().lower()
            if another != 'y':
                break
                
        print("\n👋 Registration session complete")

def main():
    if len(sys.argv) == 1:
        registration = FingerprintRegistration()
        registration.interactive_register()
        
    elif len(sys.argv) == 2:
        if sys.argv[1] == "--help":
            print("Fingerprint Registration Tool")
            print()
            print("Usage:")
            print("  python3 register_fingerprint.py                    # Interactive mode")
            print("  python3 register_fingerprint.py <username>         # Register single user")
            print("  python3 register_fingerprint.py <user1> <user2>... # Register multiple users")
            print()
            print("Examples:")
            print("  python3 register_fingerprint.py")
            print("  python3 register_fingerprint.py alice")
            print("  python3 register_fingerprint.py alice bob charlie")
            return
        else:
            username = sys.argv[1]
            registration = FingerprintRegistration()
            registration.register_fingerprint(username)
            
    else:
        usernames = sys.argv[1:]
        registration = FingerprintRegistration()
        registration.batch_register(usernames)

if __name__ == "__main__":
    main()
