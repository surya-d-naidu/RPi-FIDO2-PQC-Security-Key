#!/usr/bin/python3

import sys
import time
import getpass
import hashlib
from r503_fingerprint import FingerprintAuth, fingerprint_user_enrollment
from atecc608b import get_secure_storage_instance

class FingerprintRegistration:
    def __init__(self):
        self.fp_auth = FingerprintAuth()
        self.secure_storage = None
        try:
            self.secure_storage = get_secure_storage_instance()
        except:
            pass
        
    def display_banner(self):
        print("=" * 60)
        print("    FIDO2 Security Key - Fingerprint Registration")
        print("=" * 60)
        print()
        
    def check_sensor_status(self):
        print("🔍 Checking fingerprint sensor...")
        if not self.fp_auth.initialize():
            print("❌ Failed to initialize fingerprint sensor")
            print("   Please check:")
            print("   - Sensor is connected to /dev/ttyUSB0")
            print("   - Proper permissions (user in dialout group)")
            print("   - Sensor power supply")
            return False
        print("✅ Fingerprint sensor initialized successfully")
        return True
        
    def get_user_info(self):
        print("\n📝 User Information")
        print("-" * 20)
        
        while True:
            username = input("Enter username: ").strip()
            if username:
                break
            print("Username cannot be empty")
            
        user_id = hashlib.sha256(username.encode()).hexdigest()[:8]
        print(f"Generated User ID: {user_id}")
        
        return username, user_id
        
    def check_existing_enrollments(self):
        print("\n📊 Checking existing enrollments...")
        try:
            count = self.fp_auth.get_enrolled_count()
            print(f"Current enrolled fingerprints: {count}")
            
            if count >= 300:
                print("⚠️  Sensor memory is full. Consider clearing old enrollments.")
                choice = input("Clear all enrollments? (y/N): ").lower()
                if choice == 'y':
                    if self.fp_auth.clear_all_fingerprints():
                        print("✅ All enrollments cleared")
                    else:
                        print("❌ Failed to clear enrollments")
                        return False
            return True
        except Exception as e:
            print(f"⚠️  Could not check enrollments: {e}")
            return True
            
    def enroll_fingerprint(self, user_id):
        print(f"\n👆 Fingerprint Enrollment for User ID: {user_id}")
        print("-" * 40)
        
        numeric_user_id = int(user_id, 16) % 300
        
        print("Please follow these steps:")
        print("1. Place your finger on the sensor when prompted")
        print("2. Lift your finger when LED turns off")
        print("3. Place the same finger again for verification")
        print("4. Keep finger steady during scanning")
        print()
        
        attempts = 3
        for attempt in range(attempts):
            print(f"Enrollment attempt {attempt + 1}/{attempts}")
            input("Press Enter when ready to start enrollment...")
            
            print("👆 Place your finger on the sensor...")
            
            try:
                if fingerprint_user_enrollment(numeric_user_id):
                    print("✅ Fingerprint enrolled successfully!")
                    
                    if self.secure_storage:
                        template_hash = f"user_{user_id}_template"
                        if self.secure_storage.store_fingerprint_template_hash(template_hash):
                            print("✅ Template hash stored in secure element")
                        else:
                            print("⚠️  Could not store template hash in secure element")
                    
                    return True
                else:
                    print(f"❌ Enrollment failed (attempt {attempt + 1})")
                    if attempt < attempts - 1:
                        print("Please try again...")
                        time.sleep(2)
                        
            except Exception as e:
                print(f"❌ Enrollment error: {e}")
                if attempt < attempts - 1:
                    print("Please try again...")
                    time.sleep(2)
                    
        return False
        
    def verify_enrollment(self, user_id):
        print("\n🔐 Verifying enrollment...")
        print("Place your enrolled finger on the sensor for verification...")
        
        try:
            if self.fp_auth.verify_fingerprint():
                print("✅ Fingerprint verification successful!")
                return True
            else:
                print("❌ Fingerprint verification failed")
                return False
        except Exception as e:
            print(f"❌ Verification error: {e}")
            return False
            
    def save_user_mapping(self, username, user_id):
        try:
            mapping_file = "/etc/fido2_security_key/user_mappings.txt"
            import os
            os.makedirs(os.path.dirname(mapping_file), exist_ok=True)
            
            with open(mapping_file, "a") as f:
                f.write(f"{user_id}:{username}:{int(time.time())}\n")
            print(f"✅ User mapping saved to {mapping_file}")
            return True
        except Exception as e:
            print(f"⚠️  Could not save user mapping: {e}")
            return False
            
    def cleanup(self):
        if self.fp_auth:
            self.fp_auth.cleanup()
        if self.secure_storage:
            self.secure_storage.cleanup()
            
    def run_registration(self):
        try:
            self.display_banner()
            
            if not self.check_sensor_status():
                return False
                
            if not self.check_existing_enrollments():
                return False
                
            username, user_id = self.get_user_info()
            
            if not self.enroll_fingerprint(user_id):
                print("\n❌ Fingerprint registration failed!")
                return False
                
            if not self.verify_enrollment(user_id):
                print("\n⚠️  Enrollment completed but verification failed")
                print("   You may want to try enrolling again")
                
            self.save_user_mapping(username, user_id)
            
            print("\n🎉 Fingerprint registration completed successfully!")
            print(f"   Username: {username}")
            print(f"   User ID: {user_id}")
            print("\nYou can now use your fingerprint with the FIDO2 security key.")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Registration cancelled by user")
            return False
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            return False
        finally:
            self.cleanup()

def show_usage():
    print("Usage: python3 register_fingerprint.py [options]")
    print()
    print("Options:")
    print("  --list-users    Show registered users")
    print("  --clear-all     Clear all fingerprint enrollments")
    print("  --help          Show this help message")
    print()

def list_registered_users():
    try:
        mapping_file = "/etc/fido2_security_key/user_mappings.txt"
        with open(mapping_file, "r") as f:
            lines = f.readlines()
            
        if not lines:
            print("No registered users found")
            return
            
        print("Registered Users:")
        print("-" * 50)
        print(f"{'User ID':<10} {'Username':<20} {'Registered':<15}")
        print("-" * 50)
        
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                user_id, username, timestamp = parts[0], parts[1], parts[2]
                date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(timestamp)))
                print(f"{user_id:<10} {username:<20} {date_str:<15}")
                
    except FileNotFoundError:
        print("No user mappings file found")
    except Exception as e:
        print(f"Error reading user mappings: {e}")

def clear_all_enrollments():
    print("⚠️  This will delete ALL fingerprint enrollments!")
    confirm = input("Type 'DELETE' to confirm: ")
    
    if confirm != "DELETE":
        print("Operation cancelled")
        return
        
    try:
        fp_auth = FingerprintAuth()
        if fp_auth.initialize():
            if fp_auth.clear_all_fingerprints():
                print("✅ All fingerprint enrollments cleared")
                
                mapping_file = "/etc/fido2_security_key/user_mappings.txt"
                try:
                    import os
                    os.remove(mapping_file)
                    print("✅ User mappings cleared")
                except:
                    pass
            else:
                print("❌ Failed to clear enrollments")
        else:
            print("❌ Could not initialize fingerprint sensor")
        fp_auth.cleanup()
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            show_usage()
            return
        elif sys.argv[1] == "--list-users":
            list_registered_users()
            return
        elif sys.argv[1] == "--clear-all":
            clear_all_enrollments()
            return
        else:
            print(f"Unknown option: {sys.argv[1]}")
            show_usage()
            return
    
    registration = FingerprintRegistration()
    success = registration.run_registration()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
