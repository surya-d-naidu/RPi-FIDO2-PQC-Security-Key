#!/usr/bin/python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from r503_fingerprint import FingerprintAuth

def test_sensor():
    print("Testing fingerprint sensor connection...")
    
    fp_auth = FingerprintAuth(sensor_type='R502')
    
    print(f"Using port: {fp_auth.sensor_port}")
    print(f"Sensor type: {fp_auth.sensor_type}")
    print(f"Max templates: {fp_auth.max_templates}")
    
    print("\n1. Testing serial connection...")
    if fp_auth.sensor.connect():
        print("✅ Serial connection successful")
        
        print("\n2. Testing password verification...")
        if fp_auth.sensor.verify_password():
            print("✅ Password verification successful")
            
            print("\n3. Getting system parameters...")
            params = fp_auth.sensor.read_system_params()
            if params:
                print(f"✅ System params: {params.hex()}")
            else:
                print("❌ Could not read system parameters")
                
            print("\n4. Getting template count...")
            count = fp_auth.sensor.get_template_count()
            print(f"📊 Template count: {count}")
            
            print("\n5. Testing LED control...")
            if fp_auth.sensor.led_control(6, 0x80, 2, 3):
                print("✅ LED control successful")
            else:
                print("❌ LED control failed")
                
        else:
            print("❌ Password verification failed")
            print("   This could mean:")
            print("   - Sensor is not responding")
            print("   - Wrong sensor type")
            print("   - Communication issue")
            
        fp_auth.sensor.disconnect()
    else:
        print("❌ Serial connection failed")
        print("   Possible issues:")
        print("   - /dev/ttyS0 does not exist or no permission")
        print("   - UART not enabled in raspi-config")
        print("   - Sensor not connected properly")
        print("   - Wrong port (try /dev/ttyAMA0)")
        
    fp_auth.cleanup()

if __name__ == "__main__":
    test_sensor()
