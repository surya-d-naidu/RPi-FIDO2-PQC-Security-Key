#!/bin/bash

echo "Setting up ATECC608B dependencies..."

# Update package list
sudo apt update

# Install I2C tools and Python dependencies
sudo apt install -y i2c-tools python3-smbus python3-pip

# Enable I2C interface
sudo raspi-config nonint do_i2c 0

# Install Python packages
pip3 install smbus2

# Add user to i2c group
sudo usermod -a -G i2c $USER

# Create I2C device rules
echo 'SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0664"' | sudo tee /etc/udev/rules.d/99-i2c.rules

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

echo "Setup complete. Please reboot to ensure I2C is properly enabled."
echo "After reboot, you can test I2C with: i2cdetect -y 1"
echo "ATECC608B should appear at address 0x60"
