# O.W.A.S.A.K.A. SIEM - Deployment Guide

## Overview

Deployment instructions for O.W.A.S.A.K.A. SIEM on dedicated air-gapped hardware.

**Status**: PHASE 0 - Foundation (deployment procedures in development)

---

## Prerequisites

### Hardware Requirements

- **CPU**: 4+ cores (8+ recommended)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**:
  - 100GB local SSD (for OS and temporary data)
  - Multi-TB NAS cluster (for persistent storage)
- **Network**: Gigabit Ethernet (10GbE recommended)

### Software Requirements

- **OS**: Linux (Ubuntu 22.04+ or Debian 12+ recommended)
- **Go**: 1.22+ (for building from source)
- **Firefox ESR**: Latest (for browser integration)
- **Docker**: Optional (for containerized deployment)

---

## Installation Methods

### Method 1: Binary Installation (Recommended)

#### Step 1: Download Binary

```bash
# Download latest release (future)
wget https://github.com/VoidNxSEC/O.W.A.S.A.K.A/releases/latest/download/oswaka-linux-amd64

# Make executable
chmod +x oswaka-linux-amd64
mv oswaka-linux-amd64 /usr/local/bin/oswaka
```

#### Step 2: Create Configuration

```bash
# Create directories
sudo mkdir -p /etc/oswaka
sudo mkdir -p /var/lib/oswaka
sudo mkdir -p /var/log/oswaka

# Copy example config
sudo cp configs/examples/default.yaml /etc/oswaka/config.yaml

# Edit configuration
sudo nano /etc/oswaka/config.yaml
```

#### Step 3: Create Systemd Service

```bash
sudo tee /etc/systemd/system/oswaka.service <<EOF
[Unit]
Description=O.W.A.S.A.K.A. SIEM
After=network.target

[Service]
Type=simple
User=oswaka
Group=oswaka
ExecStart=/usr/local/bin/oswaka --config /etc/oswaka/config.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=oswaka

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/oswaka /var/log/oswaka

[Install]
WantedBy=multi-user.target
EOF
```

#### Step 4: Create Service User

```bash
# Create user
sudo useradd -r -s /bin/false -d /var/lib/oswaka oswaka

# Set permissions
sudo chown -R oswaka:oswaka /var/lib/oswaka
sudo chown -R oswaka:oswaka /var/log/oswaka
sudo chown -R oswaka:oswaka /etc/oswaka
```

#### Step 5: Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable oswaka
sudo systemctl start oswaka

# Check status
sudo systemctl status oswaka

# View logs
sudo journalctl -u oswaka -f
```

---

### Method 2: Build from Source

#### Step 1: Clone Repository

```bash
git clone https://github.com/marcosfpina/O.W.A.S.A.K.A.git
cd O.W.A.S.A.K.A
```

#### Step 2: Build

```bash
make build

# Or for release build
make build-release
```

#### Step 3: Install

```bash
sudo make install
```

#### Step 4: Follow steps 2-5 from Method 1

---

### Method 3: Docker Deployment (Future)

```bash
# Build image
docker build -t oswaka:latest .

# Run container
docker run -d \
  --name oswaka \
  -p 8080:8080 \
  -v /etc/oswaka:/etc/oswaka:ro \
  -v /var/lib/oswaka:/var/lib/oswaka \
  oswaka:latest
```

---

## Configuration

### Minimal Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 8080

logging:
  level: "info"
  format: "json"
  output: "stdout"

network:
  discovery:
    enabled: true
    scan_interval_minutes: 60
```

### Production Configuration

See `configs/examples/default.yaml` for full configuration options.

**Key settings**:

- Enable TLS for server
- Configure NAS storage
- Enable encryption
- Set up alerting destinations
- Configure ML thresholds

---

## NAS Configuration

### NFS Mount

```bash
# Install NFS client
sudo apt install nfs-common

# Create mount point
sudo mkdir -p /mnt/oswaka_nas

# Add to /etc/fstab
nas-server:/export/oswaka /mnt/oswaka_nas nfs defaults,_netdev 0 0

# Mount
sudo mount /mnt/oswaka_nas

# Update config.yaml
storage:
  nas:
    enabled: true
    type: "nfs"
    mount_point: "/mnt/oswaka_nas"
```

### SMB/CIFS Mount

```bash
# Install CIFS utils
sudo apt install cifs-utils

# Create credentials file
sudo tee /etc/oswaka/nas-credentials <<EOF
username=oswaka
password=SecurePassword123!
EOF

sudo chmod 600 /etc/oswaka/nas-credentials

# Add to /etc/fstab
//nas-server/oswaka /mnt/oswaka_nas cifs credentials=/etc/oswaka/nas-credentials,uid=1000,gid=1000 0 0

# Mount
sudo mount /mnt/oswaka_nas
```

---

## Firewall Configuration

```bash
# Allow SIEM web interface
sudo ufw allow 8080/tcp comment 'O.W.A.S.A.K.A. Web UI'

# Allow Prometheus metrics (optional)
sudo ufw allow from 10.0.0.0/8 to any port 9090 proto tcp comment 'Prometheus metrics'

# Enable firewall
sudo ufw enable
```

---

## Security Hardening

### File Permissions

```bash
# Restrict config file
sudo chmod 600 /etc/oswaka/config.yaml

# Restrict encryption keys
sudo chmod 400 /etc/oswaka/keys/*
```

### AppArmor Profile (Future)

```bash
# TODO: Create AppArmor profile
```

### SELinux Policy (Future)

```bash
# TODO: Create SELinux policy
```

---

## Monitoring & Maintenance

### Log Rotation

```bash
# Create logrotate config
sudo tee /etc/logrotate.d/oswaka <<EOF
/var/log/oswaka/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 oswaka oswaka
    sharedscripts
    postrotate
        systemctl reload oswaka > /dev/null 2>&1 || true
    endscript
}
EOF
```

### Health Checks

```bash
# Check service status
systemctl status oswaka

# Check logs
journalctl -u oswaka --since "1 hour ago"

# Check health endpoint
curl http://localhost:8080/health

# Check metrics
curl http://localhost:8080/metrics
```

### Backup Procedures

```bash
# Backup configuration
sudo tar -czf oswaka-config-backup-$(date +%Y%m%d).tar.gz /etc/oswaka

# Backup database (when implemented)
sudo tar -czf oswaka-data-backup-$(date +%Y%m%d).tar.gz /var/lib/oswaka
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u oswaka -n 100 --no-pager

# Check config syntax
oswaka --config /etc/oswaka/config.yaml --validate

# Check permissions
ls -la /var/lib/oswaka
```

### High Memory Usage

```bash
# Check memory limits in config
grep max_memory_mb /etc/oswaka/config.yaml

# Restart service
sudo systemctl restart oswaka
```

### NAS Connection Issues

```bash
# Check mount
mount | grep oswaka_nas

# Test NAS connectivity
ping nas-server

# Check NAS logs in SIEM
grep -i nas /var/log/oswaka/oswaka.log
```

---

## Upgrade Procedure

### Binary Upgrade

```bash
# Stop service
sudo systemctl stop oswaka

# Backup old binary
sudo cp /usr/local/bin/oswaka /usr/local/bin/oswaka.old

# Download new binary
sudo wget -O /usr/local/bin/oswaka https://github.com/.../oswaka-linux-amd64

# Set permissions
sudo chmod +x /usr/local/bin/oswaka

# Start service
sudo systemctl start oswaka

# Check status
sudo systemctl status oswaka
```

### Rollback

```bash
# Stop service
sudo systemctl stop oswaka

# Restore old binary
sudo mv /usr/local/bin/oswaka.old /usr/local/bin/oswaka

# Start service
sudo systemctl start oswaka
```

---

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop oswaka
sudo systemctl disable oswaka

# Remove binary
sudo rm /usr/local/bin/oswaka

# Remove service file
sudo rm /etc/systemd/system/oswaka.service
sudo systemctl daemon-reload

# Remove data (CAUTION: Irreversible!)
sudo rm -rf /var/lib/oswaka
sudo rm -rf /var/log/oswaka
sudo rm -rf /etc/oswaka

# Remove user
sudo userdel oswaka
```

---

**Document Version**: 0.1.0
**Last Updated**: 2025-10-25
**Status**: PHASE 0 - Foundation
