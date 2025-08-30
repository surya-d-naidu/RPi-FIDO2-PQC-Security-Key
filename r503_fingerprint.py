#!/usr/bin/python3

import serial
import time
import struct
import hashlib

class R503Fingerprint:
    def __init__(self, port='/dev/ttyUSB0', baudrate=57600, address=0xFFFFFFFF):
        self.port = port
        self.baudrate = baudrate
        self.address = address
        self.serial = None
        self.packet_header = 0xEF01
        
    def connect(self):
        try:
            self.serial = serial.Serial(self.port, self.baudrate, timeout=2)
            return True
        except:
            return False
            
    def disconnect(self):
        if self.serial:
            self.serial.close()
            
    def _send_packet(self, packet_type, data):
        if not self.serial:
            return None
            
        length = len(data) + 2
        packet = struct.pack('>H', self.packet_header)
        packet += struct.pack('>I', self.address)
        packet += struct.pack('>B', packet_type)
        packet += struct.pack('>H', length)
        packet += data
        
        checksum = sum(struct.unpack('B' * len(packet[6:]), packet[6:]))
        packet += struct.pack('>H', checksum)
        
        self.serial.write(packet)
        return self._receive_packet()
        
    def _receive_packet(self):
        if not self.serial:
            return None
            
        header = self.serial.read(2)
        if len(header) != 2 or struct.unpack('>H', header)[0] != self.packet_header:
            return None
            
        address = self.serial.read(4)
        packet_type = self.serial.read(1)
        length = struct.unpack('>H', self.serial.read(2))[0]
        data = self.serial.read(length - 2)
        checksum = self.serial.read(2)
        
        return data
        
    def verify_password(self, password=0x00000000):
        data = struct.pack('>I', password)
        response = self._send_packet(0x01, b'\x13' + data)
        return response and response[0] == 0x00
        
    def get_image(self):
        response = self._send_packet(0x01, b'\x01')
        return response and response[0] == 0x00
        
    def image_to_template(self, buffer_id):
        data = struct.pack('>B', buffer_id)
        response = self._send_packet(0x01, b'\x02' + data)
        return response and response[0] == 0x00
        
    def create_template(self):
        response = self._send_packet(0x01, b'\x05')
        return response and response[0] == 0x00
        
    def store_template(self, location, buffer_id=1):
        data = struct.pack('>BB', buffer_id, location)
        response = self._send_packet(0x01, b'\x06' + data)
        return response and response[0] == 0x00
        
    def load_template(self, location, buffer_id=1):
        data = struct.pack('>BB', buffer_id, location)
        response = self._send_packet(0x01, b'\x07' + data)
        return response and response[0] == 0x00
        
    def delete_template(self, location, count=1):
        data = struct.pack('>BB', location, count)
        response = self._send_packet(0x01, b'\x0C' + data)
        return response and response[0] == 0x00
        
    def empty_database(self):
        response = self._send_packet(0x01, b'\x0D')
        return response and response[0] == 0x00
        
    def search_template(self, buffer_id=1, start_page=0, page_num=300):
        data = struct.pack('>BBB', buffer_id, start_page, page_num)
        response = self._send_packet(0x01, b'\x04' + data)
        if response and response[0] == 0x00:
            return True, struct.unpack('>HH', response[1:5])
        return False, None
        
    def fast_search(self, buffer_id=1, start_page=0, page_num=300):
        data = struct.pack('>BBB', buffer_id, start_page, page_num)
        response = self._send_packet(0x01, b'\x1B' + data)
        if response and response[0] == 0x00:
            return True, struct.unpack('>HH', response[1:5])
        return False, None
        
    def match_template(self):
        response = self._send_packet(0x01, b'\x03')
        if response and response[0] == 0x00:
            return True, struct.unpack('>H', response[1:3])[0]
        return False, 0
        
    def get_template_count(self):
        response = self._send_packet(0x01, b'\x1D')
        if response and response[0] == 0x00:
            return struct.unpack('>H', response[1:3])[0]
        return 0
        
    def read_system_params(self):
        response = self._send_packet(0x01, b'\x0F')
        if response and response[0] == 0x00:
            return response[1:]
        return None
        
    def set_password(self, new_password):
        data = struct.pack('>I', new_password)
        response = self._send_packet(0x01, b'\x12' + data)
        return response and response[0] == 0x00
        
    def set_address(self, new_address):
        data = struct.pack('>I', new_address)
        response = self._send_packet(0x01, b'\x15' + data)
        return response and response[0] == 0x00
        
    def led_control(self, control_code, speed=0x80, color_index=1, cycle_count=0):
        data = struct.pack('>BBBB', control_code, speed, color_index, cycle_count)
        response = self._send_packet(0x01, b'\x35' + data)
        return response and response[0] == 0x00

class FingerprintAuth:
    def __init__(self, sensor_port='/dev/ttyUSB0'):
        self.sensor = R503Fingerprint(sensor_port)
        self.max_templates = 300
        
    def initialize(self):
        if not self.sensor.connect():
            return False
        return self.sensor.verify_password()
        
    def enroll_fingerprint(self, user_id):
        if not self.initialize():
            return False
            
        location = user_id % self.max_templates
        
        self.sensor.led_control(1, 0x80, 1, 0)
        
        if not self.sensor.get_image():
            return False
            
        if not self.sensor.image_to_template(1):
            return False
            
        time.sleep(1)
        
        if not self.sensor.get_image():
            return False
            
        if not self.sensor.image_to_template(2):
            return False
            
        if not self.sensor.create_template():
            return False
            
        if not self.sensor.store_template(location, 1):
            return False
            
        self.sensor.led_control(6, 0x80, 1, 3)
        return True
        
    def verify_fingerprint(self, user_id=None):
        if not self.initialize():
            return False
            
        self.sensor.led_control(1, 0x80, 2, 0)
        
        if not self.sensor.get_image():
            return False
            
        if not self.sensor.image_to_template(1):
            return False
            
        if user_id is not None:
            location = user_id % self.max_templates
            if not self.sensor.load_template(location, 2):
                return False
            success, score = self.sensor.match_template()
            if success and score > 60:
                self.sensor.led_control(6, 0x80, 2, 3)
                return True
        else:
            success, result = self.sensor.fast_search(1, 0, self.max_templates)
            if success:
                location, score = result
                if score > 60:
                    self.sensor.led_control(6, 0x80, 2, 3)
                    return True
                    
        self.sensor.led_control(6, 0x80, 3, 3)
        return False
        
    def delete_fingerprint(self, user_id):
        if not self.initialize():
            return False
            
        location = user_id % self.max_templates
        return self.sensor.delete_template(location)
        
    def clear_all_fingerprints(self):
        if not self.initialize():
            return False
        return self.sensor.empty_database()
        
    def get_enrolled_count(self):
        if not self.initialize():
            return 0
        return self.sensor.get_template_count()
        
    def cleanup(self):
        self.sensor.disconnect()

def fingerprint_user_verification():
    fp_auth = FingerprintAuth()
    try:
        result = fp_auth.verify_fingerprint()
        fp_auth.cleanup()
        return result
    except:
        fp_auth.cleanup()
        return False

def fingerprint_user_enrollment(user_id):
    fp_auth = FingerprintAuth()
    try:
        result = fp_auth.enroll_fingerprint(user_id)
        fp_auth.cleanup()
        return result
    except:
        fp_auth.cleanup()
        return False

def get_fingerprint_template_hash(user_id):
    fp_auth = FingerprintAuth()
    try:
        if not fp_auth.initialize():
            return None
            
        location = user_id % fp_auth.max_templates
        if fp_auth.sensor.load_template(location, 1):
            template_data = b"template_" + str(user_id).encode()
            template_hash = hashlib.sha256(template_data).digest()
            fp_auth.cleanup()
            return template_hash
        fp_auth.cleanup()
        return None
    except:
        fp_auth.cleanup()
        return None

def fingerprint_presence_detection():
    fp_auth = FingerprintAuth()
    try:
        if not fp_auth.initialize():
            return False
        result = fp_auth.sensor.get_image()
        fp_auth.cleanup()
        return result
    except:
        fp_auth.cleanup()
        return False
