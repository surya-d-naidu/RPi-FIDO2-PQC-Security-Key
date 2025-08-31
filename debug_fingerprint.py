#!/usr/bin/python3

import serial
import time
import struct

def test_raw_communication():
    print("=== Raw Communication Test ===")
    
    for baudrate in [57600, 9600, 115200]:
        print(f"\n--- Testing at {baudrate} baud ---")
        try:
            ser = serial.Serial('/dev/ttyS0', baudrate, timeout=2)
            time.sleep(0.1)
            
            # Test basic handshake packet
            packet_header = 0xEF01
            address = 0xFFFFFFFF
            packet_type = 0x01
            command = b'\x13\x00\x00\x00\x00'  # Verify password with default 0x00000000
            length = len(command) + 2
            
            packet = struct.pack('>H', packet_header)
            packet += struct.pack('>I', address)
            packet += struct.pack('>B', packet_type)
            packet += struct.pack('>H', length)
            packet += command
            
            # Calculate checksum
            checksum = sum(struct.unpack('B' * len(packet[6:]), packet[6:]))
            packet += struct.pack('>H', checksum)
            
            print(f"Sending: {packet.hex()}")
            ser.write(packet)
            
            # Read response
            response = ser.read(50)  # Read up to 50 bytes
            print(f"Received: {response.hex()}")
            
            if len(response) >= 9:
                header = struct.unpack('>H', response[0:2])[0]
                addr = struct.unpack('>I', response[2:6])[0]
                pkt_type = response[6]
                length = struct.unpack('>H', response[7:9])[0]
                
                print(f"Header: 0x{header:04X}")
                print(f"Address: 0x{addr:08X}")
                print(f"Packet Type: 0x{pkt_type:02X}")
                print(f"Length: {length}")
                
                if len(response) >= 9 + length:
                    data = response[9:9+length-2]
                    checksum = struct.unpack('>H', response[9+length-2:9+length])[0]
                    print(f"Data: {data.hex()}")
                    print(f"Checksum: 0x{checksum:04X}")
                    
                    if len(data) > 0:
                        status = data[0]
                        print(f"Status: 0x{status:02X}")
                        if status == 0x00:
                            print("✅ SUCCESS!")
                        else:
                            print(f"❌ Error code: 0x{status:02X}")
                            error_codes = {
                                0x01: "Packet receive error",
                                0x02: "No finger on sensor",
                                0x03: "Failed to enroll",
                                0x04: "Failed to generate character file",
                                0x05: "Failed to generate template",
                                0x06: "Failed to combine character files",
                                0x07: "Address out of range",
                                0x08: "Failed to read template",
                                0x09: "Failed to upload template",
                                0x0A: "Module failed to delete template",
                                0x0B: "Failed to clear finger library",
                                0x0C: "Failed to enter standby state",
                                0x0D: "Invalid password",
                                0x0E: "Failed to generate image",
                                0x0F: "Failed to write flash",
                                0x10: "No definition error",
                                0x11: "Invalid register number",
                                0x12: "Incorrect configuration of register",
                                0x13: "Wrong notepad page number",
                                0x14: "Failed to operate communication port",
                                0x15: "Failed to upload image"
                            }
                            if status in error_codes:
                                print(f"    {error_codes[status]}")
            else:
                print("❌ Response too short or invalid")
                
            ser.close()
            
        except Exception as e:
            print(f"❌ Error: {e}")

def test_different_addresses():
    print("\n=== Testing Different Addresses ===")
    
    addresses = [0xFFFFFFFF, 0x00000000, 0x01234567]
    
    for addr in addresses:
        print(f"\n--- Testing address 0x{addr:08X} ---")
        try:
            ser = serial.Serial('/dev/ttyS0', 57600, timeout=2)
            time.sleep(0.1)
            
            packet_header = 0xEF01
            packet_type = 0x01
            command = b'\x13\x00\x00\x00\x00'
            length = len(command) + 2
            
            packet = struct.pack('>H', packet_header)
            packet += struct.pack('>I', addr)
            packet += struct.pack('>B', packet_type)
            packet += struct.pack('>H', length)
            packet += command
            
            checksum = sum(struct.unpack('B' * len(packet[6:]), packet[6:]))
            packet += struct.pack('>H', checksum)
            
            ser.write(packet)
            response = ser.read(20)
            
            if len(response) >= 10 and response[9] == 0x00:
                print(f"✅ SUCCESS with address 0x{addr:08X}")
                return addr
            else:
                print(f"❌ Failed with address 0x{addr:08X}")
                
            ser.close()
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    return None

if __name__ == "__main__":
    test_raw_communication()
    working_addr = test_different_addresses()
    
    if working_addr:
        print(f"\n🎉 Working address found: 0x{working_addr:08X}")
    else:
        print("\n❌ No working configuration found")
        print("This might be a different sensor model (R305, AS608, etc.)")
