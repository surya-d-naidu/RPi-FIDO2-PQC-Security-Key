#!/usr/bin/python3

import time
import hashlib
import struct
import binascii

try:
    import board
    import busio
    from adafruit_atecc import ATECC
    ADAFRUIT_ATECC_AVAILABLE = True
except ImportError:
    ADAFRUIT_ATECC_AVAILABLE = False

class ATECC608B:
    def __init__(self, i2c_address=0x60):
        self.i2c_address = i2c_address
        self.is_initialized = False
        self.use_adafruit = ADAFRUIT_ATECC_AVAILABLE
        self.atecc = None
        
    def connect(self):
        if not self.use_adafruit:
            self.is_initialized = True
            return True
            
        try:
            i2c = busio.I2C(board.SCL, board.SDA)
            self.atecc = ATECC(i2c, address=self.i2c_address)
            self.is_initialized = True
            return True
        except Exception as e:
            print(f"ATECC608B connection failed: {e}")
            return False
            
    def disconnect(self):
        self.is_initialized = False
        self.atecc = None
            
    def get_serial_number(self):
        if not self.is_initialized:
            return None
        if not self.use_adafruit:
            return bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE])
            
        try:
            return self.atecc.serial_number
        except:
            return None
    
    def get_random(self):
        if not self.is_initialized:
            return None
        if not self.use_adafruit:
            import random
            return bytearray([random.randint(0, 255) for _ in range(32)])
            
        try:
            return self.atecc.random()
        except:
            return None
    
    def generate_key_pair(self, slot=0):
        if not self.is_initialized:
            return None
        if not self.use_adafruit:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
            
        try:
            return self.atecc.gen_key(slot, private_key=True)
        except:
            return None
    
    def get_public_key(self, slot=0):
        if not self.is_initialized:
            return None
        if not self.use_adafruit:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
            
        try:
            return self.atecc.get_public_key(slot)
        except:
            return None
    
    def sign_data(self, slot, data):
        if not self.is_initialized:
            return None
        if len(data) != 32:
            data = hashlib.sha256(data).digest()
        
        if not self.use_adafruit:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
        
        try:
            return self.atecc.sign(slot, data)
        except:
            return None
    
    def write_data_slot(self, slot, data):
        if not self.is_initialized:
            return False
        if not self.use_adafruit:
            return True
            
        try:
            self.atecc.write(slot, data)
            return True
        except:
            return False
    
    def read_data_slot(self, slot, length=32):
        if not self.is_initialized:
            return None
        if not self.use_adafruit:
            return bytearray([0] * length)
            
        try:
            return self.atecc.read(slot, length)
        except:
            return None

class SecureKeyStorage:
    def __init__(self):
        self.atecc = ATECC608B()
        self.is_initialized = False
        
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
            return False
            
        self.is_initialized = True
        return True
    
    def cleanup(self):
        if self.atecc:
            self.atecc.disconnect()
        self.is_initialized = False
    
    def get_device_serial(self):
        if not self.is_initialized:
            return None
        serial = self.atecc.get_serial_number()
        if serial:
            return binascii.hexlify(bytes(serial)).decode()
        return None
    
    def generate_device_key(self, slot=0):
        if not self.is_initialized:
            return None
        public_key = self.atecc.generate_key_pair(slot)
        if public_key:
            return binascii.hexlify(bytes(public_key)).decode()
        return None
    
    def sign_with_device_key(self, slot, data):
        if not self.is_initialized:
            return None
            
        if len(data) != 32:
            data = hashlib.sha256(data).digest()
        
        signature = self.atecc.sign_data(slot, list(data))
        if signature:
            return binascii.hexlify(bytes(signature)).decode()
        return None
    
    def get_hardware_random(self):
        if not self.is_initialized:
            return None
        random_data = self.atecc.get_random()
        if random_data:
            return binascii.hexlify(bytes(random_data)).decode()
        return None
    
    def store_credential_id(self, slot, cred_id):
        if not self.is_initialized or len(cred_id) > 32:
            return False
        
        padded_data = cred_id.ljust(32, b'\x00')
        return self.atecc.write_data_slot(slot, list(padded_data))
    
    def retrieve_credential_id(self, slot):
        if not self.is_initialized:
            return None
        
        data = self.atecc.read_data_slot(slot, 32)
        if data:
            return bytes(data).rstrip(b'\x00')
        return None
    
    def store_rp_hash(self, slot, rp_id):
        if not self.is_initialized:
            return False
        
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        return self.atecc.write_data_slot(slot, list(rp_hash))
    
    def verify_rp_hash(self, slot, rp_id):
        if not self.is_initialized:
            return False
        
        stored_hash = self.atecc.read_data_slot(slot, 32)
        if stored_hash:
            current_hash = hashlib.sha256(rp_id.encode()).digest()
            return bytes(stored_hash) == current_hash
        return False
    
    def store_fingerprint_template_hash(self, template_data):
        if not self.is_initialized:
            return False
        
        slot = 10
        template_hash = hashlib.sha256(template_data.encode()).digest()
        return self.atecc.write_data_slot(slot, list(template_hash))
    
    def verify_fingerprint_template_hash(self, template_data):
        if not self.is_initialized:
            return False
        
        slot = 10
        stored_hash = self.atecc.read_data_slot(slot, 32)
        if stored_hash:
            current_hash = hashlib.sha256(template_data.encode()).digest()
            return bytes(stored_hash) == current_hash
        return False
    
    def increment_sign_counter(self, rp_id):
        if not self.is_initialized:
            return 0
        
        slot = 12
        counter_data = self.atecc.read_data_slot(slot, 4)
        
        if counter_data:
            current_count = struct.unpack('<I', bytes(counter_data))[0]
        else:
            current_count = 0
        
        new_count = current_count + 1
        counter_bytes = list(struct.pack('<I', new_count))
        
        if self.atecc.write_data_slot(slot, counter_bytes):
            return new_count
        return current_count
    
    def get_sign_counter(self):
        if not self.is_initialized:
            return 0
        
        slot = 12
        counter_data = self.atecc.read_data_slot(slot, 4)
        
        if counter_data:
            return struct.unpack('<I', bytes(counter_data))[0]
        return 0
    
    def store_device_aaguid(self, aaguid_bytes):
        if not self.is_initialized or len(aaguid_bytes) != 16:
            return False
        
        slot = 11
        padded_data = list(aaguid_bytes) + [0] * 16
        return self.atecc.write_data_slot(slot, padded_data[:32])
    
    def get_device_aaguid(self):
        if not self.is_initialized:
            return None
        
        slot = 11
        data = self.atecc.read_data_slot(slot, 16)
        if data:
            return bytes(data)
        return None
    
    def secure_delete_slot(self, slot):
        if not self.is_initialized:
            return False
        
        random_data = self.atecc.get_random()
        if random_data:
            return self.atecc.write_data_slot(slot, list(random_data))
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
