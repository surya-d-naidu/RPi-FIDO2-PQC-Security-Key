#!/usr/bin/python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from r503_fingerprint import FingerprintAuth

def test_sensor():
    print("Testing fingerprint sensor connection...")
    
    # Test both sensor types
    for sensor_type in ['R502', 'R503']:
        print(f"\n=== Testing as {sensor_type} ===")
        fp_auth = FingerprintAuth(sensor_type=sensor_type)
        
        print(f"Using port: {fp_auth.sensor_port}")
        print(f"Sensor type: {fp_auth.sensor_type}")
        print(f"Max templates: {fp_auth.max_templates}")
        
        print("\n1. Testing serial connection...")
        if fp_auth.sensor.connect():
            print("✅ Serial connection successful")
            
            print("\n2. Testing password verification...")
            if fp_auth.sensor.verify_password():
                print("✅ Password verification successful")
                print(f"🎯 Correct sensor type: {sensor_type}")
                
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
                    
                fp_auth.sensor.disconnect()
                fp_auth.cleanup()
                return sensor_type
                
            else:
                print(f"❌ Password verification failed for {sensor_type}")
                
            fp_auth.sensor.disconnect()
        else:
            print("❌ Serial connection failed")
            
        fp_auth.cleanup()
    
    print("\n❌ Neither R502 nor R503 worked")
    print("   Possible issues:")
    print("   - Different sensor model")
    print("   - Wrong baudrate (try 9600 or 115200)")
    print("   - Hardware connection issue")
    print("   - Sensor needs different initialization")
    
    return None

if __name__ == "__main__":
    working_sensor = test_sensor()
    if working_sensor:
        print(f"\n🎉 Success! Your sensor is: {working_sensor}")
        print(f"Use FingerprintAuth(sensor_type='{working_sensor}') in your code")
    else:
        print("\n🔧 Try different baudrates...")
        for baudrate in [9600, 115200]:
            print(f"\n=== Testing baudrate {baudrate} ===")
            from r503_fingerprint import FingerprintSensorBase
            sensor = FingerprintSensorBase(baudrate=baudrate)
            if sensor.connect():
                print(f"✅ Connected at {baudrate} baud")
                if sensor.verify_password():
                    print(f"🎯 Working baudrate: {baudrate}")
                    break
                sensor.disconnect()
            else:
                print(f"❌ Failed at {baudrate} baud")
