#!/usr/bin/python3

import smbus
import time
import hashlib
import struct
import binascii

class ATECC608B:
    def __init__(self, i2c_address=0x60, i2c_bus=1):
        self.i2c_address = i2c_address
        self.i2c_bus = i2c_bus
        self.bus = None
        self.wake_delay = 0.0015
        self.execution_delay = 0.05
        
    def connect(self):
        try:
            self.bus = smbus.SMBus(self.i2c_bus)
            return self.wake_device()
        except Exception as e:
            print(f"ATECC608B connection failed: {e}")
            return False
            
    def disconnect(self):
        if self.bus:
            self.sleep_device()
            self.bus.close()
            
    def wake_device(self):
        try:
            wake_sequence = [0x00]
            self.bus.write_i2c_block_data(0x00, 0x00, wake_sequence)
            time.sleep(self.wake_delay)
            
            response = self.bus.read_i2c_block_data(self.i2c_address, 0x00, 4)
            return response == [0x04, 0x11, 0x33, 0x43]
        except:
            return False
    
    def sleep_device(self):
        try:
            sleep_cmd = [0x01]
            self.bus.write_i2c_block_data(self.i2c_address, 0x00, sleep_cmd)
            return True
        except:
            return False
    
    def _calculate_crc(self, data):
        crc = 0x0000
        for byte in data:
            for bit in range(8):
                if ((crc & 0x8000) >> 8) ^ (byte & 0x80):
                    crc = (crc << 1) ^ 0x8005
                else:
                    crc = crc << 1
                crc &= 0xFFFF
                byte <<= 1
        return [(crc >> 8) & 0xFF, crc & 0xFF]
    
    def _send_command(self, opcode, param1, param2, data=None):
        if not self.bus:
            return None
            
        command = [opcode, param1] + list(param2.to_bytes(2, 'little'))
        if data:
            command.extend(data)
            
        packet_size = len(command) + 3
        packet = [packet_size] + command
        crc = self._calculate_crc(packet[1:])
        packet.extend(crc)
        
        try:
            self.bus.write_i2c_block_data(self.i2c_address, 0x00, packet)
            time.sleep(self.execution_delay)
            
            response_length = self.bus.read_byte(self.i2c_address)
            if response_length < 4:
                return None
                
            response = [response_length] + self.bus.read_i2c_block_data(self.i2c_address, 0x00, response_length - 1)
            
            received_crc = response[-2:]
            calculated_crc = self._calculate_crc(response[:-2])
            
            if received_crc == calculated_crc:
                return response[1:-2]
            return None
        except Exception as e:
            print(f"Command failed: {e}")
            return None
    
    def info_command(self):
        response = self._send_command(0x30, 0x00, 0x0000)
        if response and len(response) >= 4:
            return response
        return None
    
    def random_command(self):
        response = self._send_command(0x1B, 0x00, 0x0000)
        if response and len(response) >= 32:
            return response[:32]
        return None
    
    def genkey_command(self, slot):
        response = self._send_command(0x40, 0x04, slot)
        if response and len(response) >= 64:
            return response[:64]
        return None
    
    def sign_command(self, slot, message_hash):
        if len(message_hash) != 32:
            return None
        response = self._send_command(0x41, 0x80, slot, message_hash)
        if response and len(response) >= 64:
            return response[:64]
        return None
    
    def read_command(self, zone, slot, offset, length):
        param2 = (slot << 3) | (offset >> 3)
        response = self._send_command(0x02, zone, param2)
        if response and len(response) >= length:
            return response[:length]
        return None
    
    def write_command(self, zone, slot, offset, data):
        param2 = (slot << 3) | (offset >> 3)
        response = self._send_command(0x12, zone, param2, data)
        return response is not None and len(response) == 1 and response[0] == 0x00

class SecureKeyStorage:
    def __init__(self, i2c_address=0x60, i2c_bus=1):
        self.atecc = ATECC608B(i2c_address, i2c_bus)
        self.is_initialized = False
        self.device_info = None
        
        self.key_slots = {
            0: 'device_identity',
            1: 'attestation_key', 
            2: 'user_key_1',
            3: 'user_key_2',
            4: 'user_key_3',
            5: 'user_key_4',
            6: 'user_key_5',
            7: 'user_key_6'
        }
        
        self.data_slots = {
            8: 'credential_metadata',
            9: 'user_data',
            10: 'fingerprint_hash',
            11: 'device_config',
            12: 'rp_counters',
            13: 'backup_data',
            14: 'temp_storage',
            15: 'system_data'
        }
    
    def initialize(self):
        if not self.atecc.connect():
            print("Failed to connect to ATECC608B")
            return False
            
        self.device_info = self.atecc.info_command()
        if not self.device_info:
            print("Failed to get device info")
            return False
            
        print(f"ATECC608B connected successfully")
        print(f"Device info: {binascii.hexlify(bytes(self.device_info)).decode()}")
        self.is_initialized = True
        return True
    
    def cleanup(self):
        if self.atecc:
            self.atecc.disconnect()
        self.is_initialized = False
    
    def get_device_serial(self):
        if not self.is_initialized:
            return None
        if self.device_info and len(self.device_info) >= 9:
            return binascii.hexlify(bytes(self.device_info[:9])).decode()
        return None
    
    def generate_device_key(self, slot=0):
        if not self.is_initialized:
            return None
        public_key = self.atecc.genkey_command(slot)
        if public_key:
            return binascii.hexlify(bytes(public_key)).decode()
        return None
    
    def sign_with_device_key(self, slot, data):
        if not self.is_initialized:
            return None
            
        if len(data) != 32:
            data = hashlib.sha256(data).digest()
        
        signature = self.atecc.sign_command(slot, list(data))
        if signature:
            return binascii.hexlify(bytes(signature)).decode()
        return None
    
    def get_hardware_random(self):
        if not self.is_initialized:
            return None
        random_data = self.atecc.random_command()
        if random_data:
            return binascii.hexlify(bytes(random_data)).decode()
        return None
    
    def store_credential_id(self, slot, cred_id):
        if not self.is_initialized or len(cred_id) > 32:
            return False
        
        padded_data = cred_id.ljust(32, b'\x00')
        return self.atecc.write_command(0x02, slot, 0, list(padded_data))
    
    def retrieve_credential_id(self, slot):
        if not self.is_initialized:
            return None
        
        data = self.atecc.read_command(0x02, slot, 0, 32)
        if data:
            return bytes(data).rstrip(b'\x00')
        return None
    
    def store_rp_hash(self, slot, rp_id):
        if not self.is_initialized:
            return False
        
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        return self.atecc.write_command(0x02, slot, 0, list(rp_hash))
    
    def verify_rp_hash(self, slot, rp_id):
        if not self.is_initialized:
            return False
        
        stored_hash = self.atecc.read_command(0x02, slot, 0, 32)
        if stored_hash:
            current_hash = hashlib.sha256(rp_id.encode()).digest()
            return bytes(stored_hash) == current_hash
        return False
    
    def store_fingerprint_template_hash(self, template_data):
        if not self.is_initialized:
            return False
        
        slot = 10
        template_hash = hashlib.sha256(template_data.encode()).digest()
        return self.atecc.write_command(0x02, slot, 0, list(template_hash))
    
    def verify_fingerprint_template_hash(self, template_data):
        if not self.is_initialized:
            return False
        
        slot = 10
        stored_hash = self.atecc.read_command(0x02, slot, 0, 32)
        if stored_hash:
            current_hash = hashlib.sha256(template_data.encode()).digest()
            return bytes(stored_hash) == current_hash
        return False
    
    def increment_sign_counter(self, rp_id):
        if not self.is_initialized:
            return 0
        
        slot = 12
        counter_data = self.atecc.read_command(0x02, slot, 0, 4)
        
        if counter_data:
            current_count = struct.unpack('<I', bytes(counter_data))[0]
        else:
            current_count = 0
        
        new_count = current_count + 1
        counter_bytes = list(struct.pack('<I', new_count))
        
        if self.atecc.write_command(0x02, slot, 0, counter_bytes):
            return new_count
        return current_count
    
    def get_sign_counter(self):
        if not self.is_initialized:
            return 0
        
        slot = 12
        counter_data = self.atecc.read_command(0x02, slot, 0, 4)
        
        if counter_data:
            return struct.unpack('<I', bytes(counter_data))[0]
        return 0
    
    def store_device_aaguid(self, aaguid_bytes):
        if not self.is_initialized or len(aaguid_bytes) != 16:
            return False
        
        slot = 11
        padded_data = list(aaguid_bytes) + [0] * 16
        return self.atecc.write_command(0x02, slot, 0, padded_data[:32])
    
    def get_device_aaguid(self):
        if not self.is_initialized:
            return None
        
        slot = 11
        data = self.atecc.read_command(0x02, slot, 0, 16)
        if data:
            return bytes(data)
        return None
    
    def secure_delete_slot(self, slot):
        if not self.is_initialized:
            return False
        
        random_data = self.atecc.random_command()
        if random_data:
            return self.atecc.write_command(0x02, slot, 0, random_data)
        return False
    
    def health_check(self):
        if not self.is_initialized:
            return False
        
        test_random = self.get_hardware_random()
        return test_random is not None and len(test_random) == 64

def get_secure_storage_instance():
    storage = SecureKeyStorage()
    if storage.initialize():
        return storage
    return None
