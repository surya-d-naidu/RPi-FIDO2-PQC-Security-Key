#!/usr/bin/python3

import sys
import time
from atecc608b import get_secure_storage_instance

def test_atecc608b():
    print("Testing ATECC608B connection...")
    
    storage = get_secure_storage_instance()
    if not storage:
        print("❌ Failed to initialize ATECC608B")
        return False
    
    print("✅ ATECC608B initialized successfully")
    
    # Get device serial
    serial = storage.get_device_serial()
    if serial:
        print(f"📱 Device Serial: {serial}")
    else:
        print("⚠️  Could not read device serial")
    
    # Test hardware random number generation
    random_data = storage.get_hardware_random()
    if random_data:
        print(f"🎲 Hardware Random: {random_data[:16]}...")
    else:
        print("⚠️  Could not generate random number")
    
    # Test key generation
    print("🔑 Testing key generation...")
    public_key = storage.generate_device_key(0)
    if public_key:
        print(f"✅ Generated key: {public_key[:16]}...")
    else:
        print("❌ Failed to generate key")
    
    # Test signing
    print("✍️  Testing signing...")
    test_data = b"Hello ATECC608B"
    signature = storage.sign_with_device_key(0, test_data)
    if signature:
        print(f"✅ Signature: {signature[:16]}...")
    else:
        print("❌ Failed to sign data")
    
    # Health check
    if storage.health_check():
        print("✅ Health check passed")
    else:
        print("❌ Health check failed")
    
    storage.cleanup()
    return True

if __name__ == "__main__":
    if test_atecc608b():
        print("\n🎉 ATECC608B test completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 ATECC608B test failed!")
        sys.exit(1)
