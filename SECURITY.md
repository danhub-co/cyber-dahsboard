# Security Guide

## Production Deployment Checklist

### 1. Environment Variables
- ✅ Use `.env` file for all credentials
- ✅ Never commit `.env` to version control
- ✅ Use strong, randomly generated passwords
- ✅ Rotate credentials regularly (every 90 days)

### 2. Network Security
```bash
# Configure firewall (UFW example)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 3000/tcp  # Grafana (or use reverse proxy)
sudo ufw deny 8087/tcp   # Block direct InfluxDB access
sudo ufw enable
```

### 3. SSL/TLS Configuration
Use a reverse proxy (Nginx/Traefik) with Let's Encrypt:

```nginx
# /etc/nginx/sites-available/grafana
server {
    listen 443 ssl http2;
    server_name dashboard.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 4. Docker Security
```yaml
# Add to docker-compose.yml services
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
```

### 5. Backup Strategy
```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backup/cyber-dashboard"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup InfluxDB
docker exec influxdb influx backup /tmp/backup
docker cp influxdb:/tmp/backup $BACKUP_DIR/influxdb_$DATE

# Backup Grafana
docker exec grafana tar czf /tmp/grafana.tar.gz /var/lib/grafana
docker cp grafana:/tmp/grafana.tar.gz $BACKUP_DIR/grafana_$DATE.tar.gz
```

### 6. Monitoring & Alerts
- Enable audit logging in InfluxDB
- Set up alerts for failed login attempts
- Monitor disk usage and set retention policies
- Configure log rotation

### 7. Access Control
```bash
# InfluxDB - Create read-only user
docker exec -it influxdb influx user create \
  --name readonly \
  --password <secure-password> \
  --org my-org

# Grant read-only access
docker exec -it influxdb influx auth create \
  --user readonly \
  --read-bucket security_logs \
  --org my-org
```

### 8. Secrets Management (Advanced)

#### Using Docker Secrets
```yaml
# docker-compose.yml
secrets:
  influxdb_password:
    file: ./secrets/influxdb_password.txt
  grafana_password:
    file: ./secrets/grafana_password.txt

services:
  influxdb:
    secrets:
      - influxdb_password
    environment:
      - DOCKER_INFLUXDB_INIT_PASSWORD_FILE=/run/secrets/influxdb_password
```

#### Using HashiCorp Vault
```bash
# Store secrets in Vault
vault kv put secret/cyber-dashboard \
  influxdb_password="<password>" \
  grafana_password="<password>"

# Retrieve in application
vault kv get -field=influxdb_password secret/cyber-dashboard
```

## Security Incident Response

### Compromised Credentials
1. Immediately rotate all passwords and tokens
2. Review access logs for unauthorized access
3. Check for data exfiltration
4. Update `.env` and restart services

### Suspicious Activity
1. Check Grafana audit logs
2. Review InfluxDB query logs
3. Analyze failed login attempts
4. Investigate network traffic patterns

## Compliance

### GDPR Considerations
- Implement data retention policies
- Enable audit logging
- Provide data export capabilities
- Document data processing activities

### SOC 2 Requirements
- Enable MFA for admin accounts
- Implement role-based access control
- Maintain audit trails
- Regular security assessments

## Security Updates
```bash
# Update all containers
docker-compose pull
docker-compose up -d

# Check for vulnerabilities
docker scan influxdb:latest
docker scan grafana/grafana:latest
docker scan telegraf:latest
```

## Contact
For security issues, please email: security@yourdomain.com
