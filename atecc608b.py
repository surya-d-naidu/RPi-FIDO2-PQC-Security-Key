#!/usr/bin/python3

import time
import hashlib
import struct
import binascii

try:
    from cryptoauthlib import *
    CRYPTOAUTHLIB_AVAILABLE = True
except ImportError:
    print("CryptoAuthLib not available, using fallback implementation")
    CRYPTOAUTHLIB_AVAILABLE = False
    
    # Define constants for fallback
    ATCA_SUCCESS = 0x00
    ATCA_ZONE_DATA = 0x02
    ATCA_I2C_IFACE = 1

class ATECC608B:
    def __init__(self, i2c_address=0x60, i2c_bus=1):
        self.i2c_address = i2c_address
        self.i2c_bus = i2c_bus
        self.is_initialized = False
        self.use_cryptoauthlib = CRYPTOAUTHLIB_AVAILABLE
        
    def connect(self):
        if not self.use_cryptoauthlib:
            print("CryptoAuthLib not available - simulating connection")
            self.is_initialized = True
            return True
            
        try:
            iface_cfg = ATCAIfaceCfg()
            iface_cfg.iface_type = ATCA_I2C_IFACE
            iface_cfg.devtype = ATCADeviceType.ATECC608B
            iface_cfg.atcai2c.slave_address = self.i2c_address
            iface_cfg.atcai2c.bus = self.i2c_bus
            iface_cfg.atcai2c.baud = 100000
            iface_cfg.wake_delay = 1500
            iface_cfg.rx_retries = 20
            
            status = atcab_init(iface_cfg)
            if status == ATCA_SUCCESS:
                self.is_initialized = True
                return True
            return False
        except Exception as e:
            print(f"ATECC608B connection failed: {e}")
            return False
            
    def disconnect(self):
        if self.is_initialized and self.use_cryptoauthlib:
            atcab_release()
        self.is_initialized = False
            
    def get_device_info(self):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            return bytearray([0x60, 0x08, 0x00, 0x00])
            
        revision = bytearray(4)
        if atcab_info(revision) == ATCA_SUCCESS:
            return revision
        return None
    
    def get_serial_number(self):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            return bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE])
            
        serial_number = bytearray(9)
        if atcab_read_serial_number(serial_number) == ATCA_SUCCESS:
            return serial_number
        return None
    
    def get_random(self):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            import random
            return bytearray([random.randint(0, 255) for _ in range(32)])
            
        random_number = bytearray(32)
        if atcab_random(random_number) == ATCA_SUCCESS:
            return random_number
        return None
    
    def generate_key_pair(self, slot=0):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
            
        public_key = bytearray(64)
        if atcab_genkey(slot, public_key) == ATCA_SUCCESS:
            return public_key
        return None
    
    def get_public_key(self, slot=0):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
            
        public_key = bytearray(64)
        if atcab_get_pubkey(slot, public_key) == ATCA_SUCCESS:
            return public_key
        return None
    
    def sign_data(self, slot, data):
        if not self.is_initialized:
            return None
        if len(data) != 32:
            data = hashlib.sha256(data).digest()
        
        if not self.use_cryptoauthlib:
            import random
            return bytearray([random.randint(0, 255) for _ in range(64)])
        
        signature = bytearray(64)
        if atcab_sign(slot, data, signature) == ATCA_SUCCESS:
            return signature
        return None
    
    def write_data_slot(self, slot, offset, data):
        if not self.is_initialized:
            return False
        if not self.use_cryptoauthlib:
            return True
            
        if atcab_write_zone(ATCA_ZONE_DATA, slot, offset, data, len(data)) == ATCA_SUCCESS:
            return True
        return False
    
    def read_data_slot(self, slot, offset, length):
        if not self.is_initialized:
            return None
        if not self.use_cryptoauthlib:
            return bytearray([0] * length)
            
        data = bytearray(length)
        if atcab_read_zone(ATCA_ZONE_DATA, slot, offset, data, length) == ATCA_SUCCESS:
            return data
        return None

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
