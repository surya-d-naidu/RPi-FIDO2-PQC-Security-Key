#!/bin/bash

echo "Setting up ATECC608B dependencies..."

# Update package list
sudo apt update

# Install I2C tools, build dependencies, and Python packages
sudo apt install -y i2c-tools python3-dev python3-pip build-essential cmake git

# Install cryptoauthlib dependencies
sudo apt install -y libusb-1.0-0-dev libudev-dev

# Clone and build cryptoauthlib
cd /tmp
git clone https://github.com/MicrochipTech/cryptoauthlib.git
cd cryptoauthlib
mkdir build && cd build
cmake .. -DATCA_HAL_I2C=ON -DATCA_PRINTF=ON -DATCA_BUILD_SHARED_LIBS=ON
make -j$(nproc)
sudo make install
sudo ldconfig

# Install Python cryptoauthlib
cd /tmp/cryptoauthlib/python
sudo python3 setup.py install

# Install additional Python packages
pip3 install smbus2

# Enable I2C interface
sudo raspi-config nonint do_i2c 0

# Add user to i2c group
sudo usermod -a -G i2c $USER

# Create I2C device rules
echo 'SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0664"' | sudo tee /etc/udev/rules.d/99-i2c.rules

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Cleanup
rm -rf /tmp/cryptoauthlib

echo "Setup complete. Please reboot to ensure I2C is properly enabled."
echo "After reboot, you can test I2C with: i2cdetect -y 1"
echo "ATECC608B should appear at address 0x60"
echo "Test with: python3 test_atecc608b.py"
