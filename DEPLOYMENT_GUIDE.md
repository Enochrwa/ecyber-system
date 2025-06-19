# AURORE Enhanced System - Production Deployment Guide

## Table of Contents

1. [Pre-deployment Checklist](#pre-deployment-checklist)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Security Hardening](#security-hardening)
4. [Database Setup](#database-setup)
5. [Backend Deployment](#backend-deployment)
6. [Frontend Deployment](#frontend-deployment)
7. [SIEM Integration Setup](#siem-integration-setup)
8. [Load Balancer Configuration](#load-balancer-configuration)
9. [Monitoring and Alerting](#monitoring-and-alerting)
10. [Backup and Recovery](#backup-and-recovery)
11. [Performance Tuning](#performance-tuning)
12. [Troubleshooting](#troubleshooting)

## Pre-deployment Checklist

### System Requirements Verification
- [ ] Operating System: Ubuntu 20.04+ or CentOS 8+
- [ ] Python 3.9+ installed
- [ ] Node.js 16.0+ installed
- [ ] Docker 20.10+ (if using containerized deployment)
- [ ] Minimum 16GB RAM (32GB recommended for production)
- [ ] Minimum 4 CPU cores (8+ recommended)
- [ ] Minimum 500GB storage (1TB+ recommended)
- [ ] Network connectivity to threat intelligence feeds
- [ ] SSL certificates for HTTPS

### Security Prerequisites
- [ ] Firewall rules configured
- [ ] VPN access configured for administration
- [ ] Multi-factor authentication setup
- [ ] Security scanning completed
- [ ] Penetration testing completed
- [ ] Compliance requirements verified

### Dependencies Installation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
sudo apt install python3.9 python3.9-dev python3-pip python3-venv -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt install nodejs -y

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Install Redis
sudo apt install redis-server -y

# Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch -y

# Install Kibana
sudo apt install kibana -y

# Install Nginx
sudo apt install nginx -y
```

## Infrastructure Requirements

### Minimum Production Setup
```
┌─────────────────────────────────────────────────────────────────┐
│                    Production Infrastructure                     │
├─────────────────────────────────────────────────────────────────┤
│  Load Balancer (Nginx/HAProxy)                                 │
│  ├── SSL Termination                                           │
│  ├── Rate Limiting                                             │
│  └── Health Checks                                             │
├─────────────────────────────────────────────────────────────────┤
│  Application Servers (2+ instances)                            │
│  ├── AURORE Backend (FastAPI)                                  │
│  ├── AURORE Frontend (React)                                   │
│  └── Performance Monitoring                                    │
├─────────────────────────────────────────────────────────────────┤
│  Database Layer                                                 │
│  ├── PostgreSQL Primary                                        │
│  ├── PostgreSQL Replica (Read-only)                           │
│  ├── Redis Cluster                                             │
│  └── Elasticsearch Cluster                                     │
├─────────────────────────────────────────────────────────────────┤
│  Monitoring & Logging                                          │
│  ├── Prometheus                                                │
│  ├── Grafana                                                   │
│  ├── ELK Stack                                                 │
│  └── Alertmanager                                              │
└─────────────────────────────────────────────────────────────────┘
```

### High Availability Setup
```
┌─────────────────────────────────────────────────────────────────┐
│                High Availability Architecture                   │
├─────────────────────────────────────────────────────────────────┤
│  External Load Balancer (AWS ALB/Azure LB/GCP LB)             │
├─────────────────────────────────────────────────────────────────┤
│  Region A                    │  Region B                       │
│  ├── Load Balancer           │  ├── Load Balancer              │
│  ├── App Servers (3x)        │  ├── App Servers (3x)           │
│  ├── PostgreSQL Master       │  ├── PostgreSQL Standby         │
│  ├── Redis Cluster (3x)      │  ├── Redis Cluster (3x)         │
│  └── Elasticsearch (3x)      │  └── Elasticsearch (3x)         │
├─────────────────────────────────────────────────────────────────┤
│  Shared Storage (NFS/S3/Azure Blob)                           │
│  Backup & Disaster Recovery                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Security Hardening

### System-level Security
```bash
# Configure firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow specific ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5432/tcp  # PostgreSQL (internal only)
sudo ufw allow 6379/tcp  # Redis (internal only)
sudo ufw allow 9200/tcp  # Elasticsearch (internal only)

# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Configure fail2ban
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit jail.local
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Application Security
```bash
# Create dedicated user for AURORE
sudo useradd -r -s /bin/false aurore
sudo mkdir -p /opt/aurore
sudo chown aurore:aurore /opt/aurore

# Set up SSL certificates (using Let's Encrypt)
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com

# Configure secure headers in Nginx
sudo tee /etc/nginx/conf.d/security.conf > /dev/null <<EOF
# Security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
add_header Referrer-Policy "strict-origin-when-cross-origin";

# Hide Nginx version
server_tokens off;
EOF
```

## Database Setup

### PostgreSQL Configuration
```bash
# Configure PostgreSQL
sudo -u postgres createuser aurore
sudo -u postgres createdb aurore_db -O aurore
sudo -u postgres psql -c "ALTER USER aurore PASSWORD 'secure_password_here';"

# Configure PostgreSQL for production
sudo tee -a /etc/postgresql/13/main/postgresql.conf > /dev/null <<EOF
# Performance tuning
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200

# Connection settings
max_connections = 200
listen_addresses = 'localhost'

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'pg_log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'mod'
log_min_duration_statement = 1000
EOF

# Configure authentication
sudo tee /etc/postgresql/13/main/pg_hba.conf > /dev/null <<EOF
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     peer
host    aurore_db       aurore          127.0.0.1/32           md5
host    aurore_db       aurore          ::1/128                 md5
EOF

sudo systemctl restart postgresql
```

### Redis Configuration
```bash
# Configure Redis for production
sudo tee /etc/redis/redis.conf > /dev/null <<EOF
# Network
bind 127.0.0.1
port 6379
protected-mode yes

# Security
requirepass secure_redis_password_here

# Memory management
maxmemory 512mb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
EOF

sudo systemctl restart redis-server
```

### Elasticsearch Configuration
```bash
# Configure Elasticsearch
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
# Cluster
cluster.name: aurore-security
node.name: aurore-node-1
node.roles: [master, data, ingest]

# Network
network.host: localhost
http.port: 9200

# Discovery
discovery.type: single-node

# Security
xpack.security.enabled: false

# Memory
bootstrap.memory_lock: true

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
EOF

# Configure JVM heap size
sudo tee /etc/elasticsearch/jvm.options.d/heap.options > /dev/null <<EOF
-Xms2g
-Xmx2g
EOF

# Enable memory lock
sudo mkdir -p /etc/systemd/system/elasticsearch.service.d
sudo tee /etc/systemd/system/elasticsearch.service.d/override.conf > /dev/null <<EOF
[Service]
LimitMEMLOCK=infinity
EOF

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

## Backend Deployment

### Environment Setup
```bash
# Create application directory
sudo mkdir -p /opt/aurore/backend
sudo chown aurore:aurore /opt/aurore/backend

# Clone repository
cd /opt/aurore
sudo -u aurore git clone https://github.com/Enochrwa/ecyber-system.git .

# Create virtual environment
cd /opt/aurore/backend
sudo -u aurore python3 -m venv venv
sudo -u aurore ./venv/bin/pip install --upgrade pip

# Install dependencies
sudo -u aurore ./venv/bin/pip install -r requirements-enhanced.txt

# Create production environment file
sudo -u aurore tee .env > /dev/null <<EOF
# Database
DATABASE_URL=postgresql://aurore:secure_password_here@localhost/aurore_db

# Redis
REDIS_URL=redis://:secure_redis_password_here@localhost:6379

# Security
SECRET_KEY=your_very_secure_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_key_here
ENCRYPTION_KEY=your_encryption_key_here

# SIEM
ELASTICSEARCH_URL=http://localhost:9200
KIBANA_URL=http://localhost:5601
SIEM_ENABLED=true

# Performance
PERFORMANCE_MONITORING=true
DATABASE_OPTIMIZATION=true

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/aurore/backend.log

# Environment
ENVIRONMENT=production
DEBUG=false
EOF

# Create log directory
sudo mkdir -p /var/log/aurore
sudo chown aurore:aurore /var/log/aurore
```

### Database Migration
```bash
# Run database migrations
cd /opt/aurore/backend
sudo -u aurore ./venv/bin/alembic upgrade head

# Create initial admin user
sudo -u aurore ./venv/bin/python -c "
from app.core.security import get_password_hash
from app.database import SessionLocal
from app.models.user import User

db = SessionLocal()
admin_user = User(
    email='admin@yourcompany.com',
    username='admin',
    hashed_password=get_password_hash('secure_admin_password'),
    is_active=True,
    is_superuser=True
)
db.add(admin_user)
db.commit()
print('Admin user created successfully')
"
```

### Systemd Service Configuration
```bash
# Create systemd service
sudo tee /etc/systemd/system/aurore-backend.service > /dev/null <<EOF
[Unit]
Description=AURORE Enhanced Cybersecurity Backend
After=network.target postgresql.service redis.service elasticsearch.service
Requires=postgresql.service redis.service

[Service]
Type=exec
User=aurore
Group=aurore
WorkingDirectory=/opt/aurore/backend
Environment=PATH=/opt/aurore/backend/venv/bin
ExecStart=/opt/aurore/backend/venv/bin/gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000 --access-logfile /var/log/aurore/access.log --error-logfile /var/log/aurore/error.log
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/aurore /opt/aurore/backend/data

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable aurore-backend
sudo systemctl start aurore-backend
```

## Frontend Deployment

### Build and Deploy
```bash
# Build frontend
cd /opt/aurore/eCyber
sudo -u aurore npm ci --production
sudo -u aurore npm run build

# Create production environment
sudo -u aurore tee .env.production > /dev/null <<EOF
VITE_API_BASE_URL=https://your-domain.com/api
VITE_WS_URL=wss://your-domain.com/ws
VITE_ENVIRONMENT=production
VITE_SENTRY_DSN=your_sentry_dsn_here
EOF

# Copy build to web directory
sudo mkdir -p /var/www/aurore
sudo cp -r dist/* /var/www/aurore/
sudo chown -R www-data:www-data /var/www/aurore
```

### Nginx Configuration
```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/aurore > /dev/null <<EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;

# Upstream backend servers
upstream aurore_backend {
    server 127.0.0.1:8000;
    # Add more backend servers for load balancing
    # server 127.0.0.1:8001;
    # server 127.0.0.1:8002;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    include /etc/nginx/conf.d/security.conf;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    # Frontend static files
    location / {
        root /var/www/aurore;
        try_files \$uri \$uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://aurore_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # WebSocket endpoints
    location /ws/ {
        proxy_pass http://aurore_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket specific timeouts
        proxy_read_timeout 86400;
    }

    # Authentication endpoints (stricter rate limiting)
    location /api/auth/ {
        limit_req zone=login burst=5 nodelay;
        
        proxy_pass http://aurore_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://aurore_backend/health;
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|conf)\$ {
        deny all;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/aurore /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## SIEM Integration Setup

### Kibana Configuration
```bash
# Configure Kibana
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
# Server
server.port: 5601
server.host: "localhost"
server.name: "aurore-kibana"

# Elasticsearch
elasticsearch.hosts: ["http://localhost:9200"]

# Security
server.ssl.enabled: false

# Logging
logging.dest: /var/log/kibana/kibana.log
logging.silent: false
logging.quiet: false
logging.verbose: false
EOF

sudo systemctl enable kibana
sudo systemctl start kibana
```

### SIEM Dashboard Setup
```bash
# Create SIEM setup script
sudo -u aurore tee /opt/aurore/backend/setup_siem.py > /dev/null <<'EOF'
#!/usr/bin/env python3
"""
SIEM setup script for AURORE Enhanced System
"""
import asyncio
import json
from app.services.siem.siem_integration import SIEMManager

async def setup_siem():
    """Setup SIEM integration with default dashboards and indices"""
    
    config = {
        'elasticsearch': {
            'host': 'localhost',
            'port': 9200,
            'scheme': 'http'
        },
        'kibana': {
            'host': 'localhost',
            'port': 5601,
            'scheme': 'http'
        }
    }
    
    siem_manager = SIEMManager(config)
    
    try:
        # Initialize SIEM
        await siem_manager.start()
        print("✓ SIEM integration initialized")
        
        # Create index templates
        await siem_manager.create_index_templates()
        print("✓ Index templates created")
        
        # Setup default dashboards
        await siem_manager.setup_default_dashboards()
        print("✓ Default dashboards created")
        
        # Create alert rules
        await siem_manager.setup_alert_rules()
        print("✓ Alert rules configured")
        
        print("\nSIEM setup completed successfully!")
        print("Access Kibana at: http://localhost:5601")
        
    except Exception as e:
        print(f"✗ SIEM setup failed: {e}")
        return False
    
    finally:
        await siem_manager.stop()
    
    return True

if __name__ == "__main__":
    asyncio.run(setup_siem())
EOF

# Run SIEM setup
cd /opt/aurore/backend
sudo -u aurore ./venv/bin/python setup_siem.py
```

## Load Balancer Configuration

### HAProxy Setup (Alternative to Nginx)
```bash
# Install HAProxy
sudo apt install haproxy -y

# Configure HAProxy
sudo tee /etc/haproxy/haproxy.cfg > /dev/null <<EOF
global
    daemon
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

    # SSL
    ssl-default-bind-ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull
    option redispatch
    retries 3

# Frontend
frontend aurore_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/aurore.pem
    redirect scheme https if !{ ssl_fc }
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if { sc_http_req_rate(0) gt 20 }
    
    # Route to backend
    default_backend aurore_backend

# Backend
backend aurore_backend
    balance roundrobin
    option httpchk GET /health
    
    # Backend servers
    server backend1 127.0.0.1:8000 check
    # server backend2 127.0.0.1:8001 check
    # server backend3 127.0.0.1:8002 check

# Stats
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF

sudo systemctl enable haproxy
sudo systemctl start haproxy
```

## Monitoring and Alerting

### Prometheus Configuration
```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
sudo mv prometheus-2.40.0.linux-amd64 /opt/prometheus
sudo useradd --no-create-home --shell /bin/false prometheus
sudo chown -R prometheus:prometheus /opt/prometheus

# Create configuration
sudo tee /opt/prometheus/prometheus.yml > /dev/null <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "aurore_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093

scrape_configs:
  - job_name: 'aurore-backend'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['localhost:9121']
EOF

# Create alert rules
sudo tee /opt/prometheus/aurore_rules.yml > /dev/null <<EOF
groups:
  - name: aurore_alerts
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% for more than 5 minutes"

      - alert: DatabaseConnectionFailure
        expr: up{job="postgres-exporter"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failure"
          description: "PostgreSQL is not responding"

      - alert: HighThreatDetectionRate
        expr: rate(aurore_threats_detected_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High threat detection rate"
          description: "Threat detection rate is unusually high"
EOF

# Create systemd service
sudo tee /etc/systemd/system/prometheus.service > /dev/null <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml --storage.tsdb.path=/opt/prometheus/data --web.console.templates=/opt/prometheus/consoles --web.console.libraries=/opt/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
```

### Grafana Setup
```bash
# Install Grafana
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install grafana -y

# Configure Grafana
sudo tee /etc/grafana/grafana.ini > /dev/null <<EOF
[server]
http_port = 3000
domain = your-domain.com
root_url = https://your-domain.com/grafana/

[security]
admin_user = admin
admin_password = secure_grafana_password

[auth]
disable_login_form = false

[auth.anonymous]
enabled = false

[database]
type = postgres
host = localhost:5432
name = grafana
user = grafana
password = grafana_db_password

[session]
provider = postgres
provider_config = user=grafana password=grafana_db_password host=localhost port=5432 dbname=grafana sslmode=disable

[analytics]
reporting_enabled = false
check_for_updates = false
EOF

# Create Grafana database
sudo -u postgres createuser grafana
sudo -u postgres createdb grafana -O grafana
sudo -u postgres psql -c "ALTER USER grafana PASSWORD 'grafana_db_password';"

sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

## Backup and Recovery

### Database Backup
```bash
# Create backup script
sudo tee /opt/aurore/scripts/backup_database.sh > /dev/null <<'EOF'
#!/bin/bash

# Configuration
BACKUP_DIR="/opt/aurore/backups"
DB_NAME="aurore_db"
DB_USER="aurore"
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Generate backup filename
BACKUP_FILE="$BACKUP_DIR/aurore_db_$(date +%Y%m%d_%H%M%S).sql.gz"

# Create database backup
pg_dump -U $DB_USER -h localhost $DB_NAME | gzip > $BACKUP_FILE

# Verify backup
if [ $? -eq 0 ]; then
    echo "Database backup created successfully: $BACKUP_FILE"
    
    # Remove old backups
    find $BACKUP_DIR -name "aurore_db_*.sql.gz" -mtime +$RETENTION_DAYS -delete
    echo "Old backups cleaned up (retention: $RETENTION_DAYS days)"
else
    echo "Database backup failed!"
    exit 1
fi

# Upload to cloud storage (optional)
# aws s3 cp $BACKUP_FILE s3://your-backup-bucket/database/
# gsutil cp $BACKUP_FILE gs://your-backup-bucket/database/
# az storage blob upload --file $BACKUP_FILE --container-name backups
EOF

chmod +x /opt/aurore/scripts/backup_database.sh

# Create cron job for daily backups
echo "0 2 * * * /opt/aurore/scripts/backup_database.sh" | sudo crontab -u aurore -
```

### Configuration Backup
```bash
# Create configuration backup script
sudo tee /opt/aurore/scripts/backup_config.sh > /dev/null <<'EOF'
#!/bin/bash

BACKUP_DIR="/opt/aurore/backups/config"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup application configuration
tar -czf "$BACKUP_DIR/aurore_config_$TIMESTAMP.tar.gz" \
    /opt/aurore/backend/.env \
    /opt/aurore/eCyber/.env.production \
    /etc/nginx/sites-available/aurore \
    /etc/systemd/system/aurore-backend.service \
    /etc/postgresql/13/main/postgresql.conf \
    /etc/redis/redis.conf \
    /etc/elasticsearch/elasticsearch.yml \
    /etc/kibana/kibana.yml

echo "Configuration backup created: $BACKUP_DIR/aurore_config_$TIMESTAMP.tar.gz"
EOF

chmod +x /opt/aurore/scripts/backup_config.sh
```

### Disaster Recovery Plan
```bash
# Create disaster recovery script
sudo tee /opt/aurore/scripts/disaster_recovery.sh > /dev/null <<'EOF'
#!/bin/bash

# Disaster Recovery Script for AURORE Enhanced System

echo "AURORE Disaster Recovery Process"
echo "================================"

# Check if backup file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <backup_file.sql.gz>"
    echo "Available backups:"
    ls -la /opt/aurore/backups/aurore_db_*.sql.gz
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Starting disaster recovery with backup: $BACKUP_FILE"

# Stop services
echo "Stopping AURORE services..."
sudo systemctl stop aurore-backend
sudo systemctl stop nginx

# Restore database
echo "Restoring database..."
sudo -u postgres dropdb aurore_db
sudo -u postgres createdb aurore_db -O aurore
gunzip -c "$BACKUP_FILE" | sudo -u postgres psql aurore_db

if [ $? -eq 0 ]; then
    echo "Database restored successfully"
else
    echo "Database restoration failed!"
    exit 1
fi

# Restart services
echo "Starting services..."
sudo systemctl start aurore-backend
sudo systemctl start nginx

# Verify services
echo "Verifying services..."
sleep 10

if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✓ Backend service is healthy"
else
    echo "✗ Backend service is not responding"
fi

if curl -f http://localhost > /dev/null 2>&1; then
    echo "✓ Frontend service is healthy"
else
    echo "✗ Frontend service is not responding"
fi

echo "Disaster recovery completed!"
EOF

chmod +x /opt/aurore/scripts/disaster_recovery.sh
```

## Performance Tuning

### System-level Optimization
```bash
# Optimize kernel parameters
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# Network optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr

# File system optimization
fs.file-max = 2097152
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
EOF

sudo sysctl -p
```

### Application Performance Tuning
```bash
# Create performance tuning script
sudo tee /opt/aurore/scripts/performance_tune.sh > /dev/null <<'EOF'
#!/bin/bash

echo "AURORE Performance Tuning"
echo "========================"

# Optimize PostgreSQL
echo "Optimizing PostgreSQL..."
sudo -u postgres psql aurore_db -c "
VACUUM ANALYZE;
REINDEX DATABASE aurore_db;
"

# Optimize Redis
echo "Optimizing Redis..."
redis-cli BGREWRITEAOF

# Clear application caches
echo "Clearing application caches..."
curl -X POST http://localhost:8000/api/v1/admin/cache/clear

# Restart services for optimal performance
echo "Restarting services..."
sudo systemctl restart aurore-backend
sudo systemctl reload nginx

echo "Performance tuning completed!"
EOF

chmod +x /opt/aurore/scripts/performance_tune.sh

# Create weekly performance tuning cron job
echo "0 3 * * 0 /opt/aurore/scripts/performance_tune.sh" | sudo crontab -u aurore -
```

## Troubleshooting

### Common Issues and Solutions

#### Backend Service Issues
```bash
# Check service status
sudo systemctl status aurore-backend

# View logs
sudo journalctl -u aurore-backend -f

# Check application logs
tail -f /var/log/aurore/backend.log
tail -f /var/log/aurore/error.log

# Test backend directly
curl http://localhost:8000/health

# Check database connectivity
sudo -u aurore psql -h localhost -U aurore aurore_db -c "SELECT 1;"
```

#### Frontend Issues
```bash
# Check Nginx status
sudo systemctl status nginx

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# Test Nginx configuration
sudo nginx -t

# Check frontend build
ls -la /var/www/aurore/
```

#### Database Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# View PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-13-main.log

# Check database connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Check database size
sudo -u postgres psql aurore_db -c "
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

#### SIEM Issues
```bash
# Check Elasticsearch status
curl http://localhost:9200/_cluster/health?pretty

# Check Elasticsearch logs
sudo tail -f /var/log/elasticsearch/aurore-security.log

# Check Kibana status
curl http://localhost:5601/api/status

# View Kibana logs
sudo tail -f /var/log/kibana/kibana.log

# Check SIEM indices
curl http://localhost:9200/_cat/indices?v
```

### Performance Monitoring
```bash
# Create monitoring script
sudo tee /opt/aurore/scripts/monitor_performance.sh > /dev/null <<'EOF'
#!/bin/bash

echo "AURORE Performance Monitor"
echo "========================="
echo "Timestamp: $(date)"
echo

# System resources
echo "System Resources:"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')"
echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
echo

# Service status
echo "Service Status:"
systemctl is-active aurore-backend && echo "✓ Backend: Running" || echo "✗ Backend: Stopped"
systemctl is-active nginx && echo "✓ Nginx: Running" || echo "✗ Nginx: Stopped"
systemctl is-active postgresql && echo "✓ PostgreSQL: Running" || echo "✗ PostgreSQL: Stopped"
systemctl is-active redis && echo "✓ Redis: Running" || echo "✗ Redis: Stopped"
systemctl is-active elasticsearch && echo "✓ Elasticsearch: Running" || echo "✗ Elasticsearch: Stopped"
echo

# Application health
echo "Application Health:"
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✓ Backend API: Healthy"
else
    echo "✗ Backend API: Unhealthy"
fi

if curl -f http://localhost > /dev/null 2>&1; then
    echo "✓ Frontend: Accessible"
else
    echo "✗ Frontend: Inaccessible"
fi

# Database connections
echo "Database Connections: $(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';")"

# Recent errors
echo
echo "Recent Errors (last 10):"
sudo tail -n 10 /var/log/aurore/error.log | grep ERROR || echo "No recent errors"

echo
echo "========================="
EOF

chmod +x /opt/aurore/scripts/monitor_performance.sh
```

### Health Check Script
```bash
# Create comprehensive health check
sudo tee /opt/aurore/scripts/health_check.sh > /dev/null <<'EOF'
#!/bin/bash

# AURORE Health Check Script
HEALTH_STATUS=0

check_service() {
    local service=$1
    local name=$2
    
    if systemctl is-active $service > /dev/null 2>&1; then
        echo "✓ $name: Running"
    else
        echo "✗ $name: Not running"
        HEALTH_STATUS=1
    fi
}

check_port() {
    local port=$1
    local name=$2
    
    if nc -z localhost $port > /dev/null 2>&1; then
        echo "✓ $name (port $port): Accessible"
    else
        echo "✗ $name (port $port): Not accessible"
        HEALTH_STATUS=1
    fi
}

check_url() {
    local url=$1
    local name=$2
    
    if curl -f $url > /dev/null 2>&1; then
        echo "✓ $name: Responding"
    else
        echo "✗ $name: Not responding"
        HEALTH_STATUS=1
    fi
}

echo "AURORE System Health Check"
echo "=========================="
echo "Timestamp: $(date)"
echo

echo "System Services:"
check_service "aurore-backend" "AURORE Backend"
check_service "nginx" "Nginx"
check_service "postgresql" "PostgreSQL"
check_service "redis" "Redis"
check_service "elasticsearch" "Elasticsearch"
check_service "kibana" "Kibana"
echo

echo "Network Connectivity:"
check_port 8000 "Backend API"
check_port 80 "HTTP"
check_port 443 "HTTPS"
check_port 5432 "PostgreSQL"
check_port 6379 "Redis"
check_port 9200 "Elasticsearch"
check_port 5601 "Kibana"
echo

echo "Application Health:"
check_url "http://localhost:8000/health" "Backend Health"
check_url "http://localhost" "Frontend"
check_url "http://localhost:9200/_cluster/health" "Elasticsearch Cluster"
echo

# Check disk space
echo "Disk Space:"
df -h | grep -E "(/$|/opt|/var)" | while read line; do
    usage=$(echo $line | awk '{print $5}' | sed 's/%//')
    mount=$(echo $line | awk '{print $6}')
    if [ $usage -gt 90 ]; then
        echo "✗ $mount: ${usage}% (Critical)"
        HEALTH_STATUS=1
    elif [ $usage -gt 80 ]; then
        echo "⚠ $mount: ${usage}% (Warning)"
    else
        echo "✓ $mount: ${usage}% (OK)"
    fi
done
echo

# Check memory usage
echo "Memory Usage:"
memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
if (( $(echo "$memory_usage > 90" | bc -l) )); then
    echo "✗ Memory: ${memory_usage}% (Critical)"
    HEALTH_STATUS=1
elif (( $(echo "$memory_usage > 80" | bc -l) )); then
    echo "⚠ Memory: ${memory_usage}% (Warning)"
else
    echo "✓ Memory: ${memory_usage}% (OK)"
fi
echo

echo "=========================="
if [ $HEALTH_STATUS -eq 0 ]; then
    echo "Overall Status: ✓ HEALTHY"
else
    echo "Overall Status: ✗ ISSUES DETECTED"
fi

exit $HEALTH_STATUS
EOF

chmod +x /opt/aurore/scripts/health_check.sh

# Create cron job for regular health checks
echo "*/5 * * * * /opt/aurore/scripts/health_check.sh >> /var/log/aurore/health_check.log 2>&1" | sudo crontab -u aurore -
```

## Final Deployment Checklist

### Pre-Production Verification
- [ ] All services are running and healthy
- [ ] SSL certificates are installed and valid
- [ ] Firewall rules are configured correctly
- [ ] Database migrations are completed
- [ ] SIEM integration is working
- [ ] Monitoring and alerting are configured
- [ ] Backup procedures are tested
- [ ] Performance tuning is applied
- [ ] Security hardening is complete
- [ ] Documentation is updated

### Go-Live Checklist
- [ ] DNS records are updated
- [ ] Load balancer is configured
- [ ] Health checks are passing
- [ ] Monitoring dashboards are accessible
- [ ] Alert notifications are working
- [ ] Backup verification is successful
- [ ] Disaster recovery plan is tested
- [ ] Team is trained on operations
- [ ] Support procedures are documented
- [ ] Rollback plan is prepared

### Post-Deployment Tasks
- [ ] Monitor system performance for 24 hours
- [ ] Verify all security features are working
- [ ] Test alert generation and response
- [ ] Validate backup and recovery procedures
- [ ] Review and optimize performance metrics
- [ ] Update documentation with any changes
- [ ] Schedule regular maintenance windows
- [ ] Plan for future scaling requirements

---

**Congratulations!** Your AURORE Enhanced Cybersecurity System is now deployed and ready for production use. The system provides enterprise-grade security capabilities with comprehensive monitoring, alerting, and management features.

