#!/usr/bin/python3

import sys
import time
import os
from r503_fingerprint import FingerprintAuth

class FingerprintManager:
    def __init__(self):
        self.fp_auth = FingerprintAuth()
        self.mapping_file = "/etc/fido2_security_key/user_mappings.txt"
        
    def display_menu(self):
        print("\n" + "=" * 50)
        print("    FIDO2 Security Key - Fingerprint Manager")
        print("=" * 50)
        print("1. List enrolled fingerprints")
        print("2. Test fingerprint verification")
        print("3. Delete specific user fingerprint")
        print("4. Clear all fingerprints")
        print("5. Sensor information")
        print("6. Exit")
        print("-" * 50)
        
    def list_enrollments(self):
        print("\n📊 Enrolled Fingerprints")
        print("-" * 30)
        
        if not self.fp_auth.initialize():
            print("❌ Could not initialize fingerprint sensor")
            return
            
        try:
            count = self.fp_auth.get_enrolled_count()
            print(f"Total enrolled: {count}")
            
            if count == 0:
                print("No fingerprints enrolled")
                return
                
            # Show user mappings if available
            try:
                with open(self.mapping_file, "r") as f:
                    lines = f.readlines()
                    
                if lines:
                    print("\nRegistered Users:")
                    print(f"{'User ID':<10} {'Username':<20} {'Date':<15}")
                    print("-" * 45)
                    
                    for line in lines:
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            user_id, username, timestamp = parts[0], parts[1], parts[2]
                            date_str = time.strftime("%m/%d/%Y", time.localtime(int(timestamp)))
                            print(f"{user_id:<10} {username:<20} {date_str:<15}")
            except FileNotFoundError:
                print("No user mapping file found")
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.fp_auth.cleanup()
            
    def test_verification(self):
        print("\n🔐 Fingerprint Verification Test")
        print("-" * 35)
        
        if not self.fp_auth.initialize():
            print("❌ Could not initialize fingerprint sensor")
            return
            
        print("Place your finger on the sensor...")
        
        try:
            start_time = time.time()
            if self.fp_auth.verify_fingerprint():
                elapsed = time.time() - start_time
                print(f"✅ Verification successful! ({elapsed:.2f}s)")
            else:
                elapsed = time.time() - start_time
                print(f"❌ Verification failed ({elapsed:.2f}s)")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.fp_auth.cleanup()
            
    def delete_user_fingerprint(self):
        print("\n🗑️  Delete User Fingerprint")
        print("-" * 30)
        
        # Show current users
        try:
            with open(self.mapping_file, "r") as f:
                lines = f.readlines()
                
            if not lines:
                print("No registered users found")
                return
                
            print("Current users:")
            users = []
            for i, line in enumerate(lines):
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    user_id, username = parts[0], parts[1]
                    users.append((user_id, username, line))
                    print(f"{i+1}. {username} (ID: {user_id})")
                    
            choice = input("\nSelect user number to delete (or 'c' to cancel): ").strip()
            
            if choice.lower() == 'c':
                return
                
            try:
                index = int(choice) - 1
                if 0 <= index < len(users):
                    user_id, username, line_to_remove = users[index]
                    
                    confirm = input(f"Delete fingerprint for '{username}'? (y/N): ")
                    if confirm.lower() != 'y':
                        return
                        
                    # Delete from sensor
                    if self.fp_auth.initialize():
                        numeric_id = int(user_id, 16) % 300
                        if self.fp_auth.delete_fingerprint(numeric_id):
                            print(f"✅ Fingerprint deleted from sensor")
                        else:
                            print("⚠️  Could not delete from sensor")
                        self.fp_auth.cleanup()
                    
                    # Remove from mapping file
                    with open(self.mapping_file, "w") as f:
                        for line in lines:
                            if line != line_to_remove:
                                f.write(line)
                    print(f"✅ User '{username}' removed from mappings")
                    
                else:
                    print("Invalid selection")
            except ValueError:
                print("Invalid input")
                
        except FileNotFoundError:
            print("No user mappings found")
        except Exception as e:
            print(f"Error: {e}")
            
    def clear_all(self):
        print("\n⚠️  Clear All Fingerprints")
        print("-" * 25)
        
        confirm = input("This will delete ALL fingerprints! Type 'DELETE' to confirm: ")
        if confirm != "DELETE":
            print("Operation cancelled")
            return
            
        if not self.fp_auth.initialize():
            print("❌ Could not initialize fingerprint sensor")
            return
            
        try:
            if self.fp_auth.clear_all_fingerprints():
                print("✅ All fingerprints cleared from sensor")
                
                # Clear mapping file
                try:
                    os.remove(self.mapping_file)
                    print("✅ User mappings cleared")
                except:
                    pass
            else:
                print("❌ Failed to clear fingerprints")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.fp_auth.cleanup()
            
    def show_sensor_info(self):
        print("\n🔍 Sensor Information")
        print("-" * 25)
        
        if not self.fp_auth.initialize():
            print("❌ Could not initialize fingerprint sensor")
            return
            
        try:
            count = self.fp_auth.get_enrolled_count()
            max_templates = self.fp_auth.max_templates
            
            print(f"Sensor Model: R503")
            print(f"Communication: UART (57600 baud)")
            print(f"Max Templates: {max_templates}")
            print(f"Enrolled Templates: {count}")
            print(f"Available Slots: {max_templates - count}")
            print(f"Usage: {(count/max_templates)*100:.1f}%")
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.fp_auth.cleanup()
            
    def run(self):
        while True:
            try:
                self.display_menu()
                choice = input("Select option (1-6): ").strip()
                
                if choice == "1":
                    self.list_enrollments()
                elif choice == "2":
                    self.test_verification()
                elif choice == "3":
                    self.delete_user_fingerprint()
                elif choice == "4":
                    self.clear_all()
                elif choice == "5":
                    self.show_sensor_info()
                elif choice == "6":
                    print("\nGoodbye!")
                    break
                else:
                    print("Invalid option. Please try again.")
                    
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
                input("Press Enter to continue...")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Fingerprint Manager - Interactive management tool")
        print("Usage: python3 fingerprint_manager.py")
        return
        
    manager = FingerprintManager()
    manager.run()

if __name__ == "__main__":
    main()
