#!/bin/bash

echo "Setting up ATECC608B with Adafruit CircuitPython libraries..."

sudo apt update

sudo apt install -y i2c-tools python3-dev python3-pip

sudo apt install -y python3-circuitpython-busio python3-circuitpython-board

pip3 install --user adafruit-circuitpython-atecc

sudo raspi-config nonint do_i2c 0

sudo usermod -a -G i2c $USER

echo 'SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0664"' | sudo tee /etc/udev/rules.d/99-i2c.rules

sudo udevadm control --reload-rules
sudo udevadm trigger

echo "Setup complete. Please reboot to ensure I2C is properly enabled."
echo "After reboot, you can test I2C with: i2cdetect -y 1"
echo "ATECC608B should appear at address 0x60"
echo "Test with: python3 test_atecc608b.py"
