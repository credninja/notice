#!/bin/bash
# NOTICE Service Installer
# Run with: sudo bash install_service.sh

set -e

echo "=== NOTICE Service Installer ==="

# Copy service file
cp /home/notice/Documents/notice/notice.service /etc/systemd/system/notice.service

# Reload systemd
systemctl daemon-reload

# Enable on boot
systemctl enable notice.service

# Start the service
systemctl start notice.service

# Check status
echo ""
echo "=== Service Status ==="
systemctl status notice.service --no-pager

echo ""
echo "=== Service Installed ==="
echo "Commands:"
echo "  sudo systemctl status notice    # Check status"
echo "  sudo systemctl restart notice   # Restart"
echo "  sudo systemctl stop notice      # Stop"
echo "  sudo journalctl -u notice -f    # View live logs"
echo ""
echo "NOTICE will now auto-start on boot."
