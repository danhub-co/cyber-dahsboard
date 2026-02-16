# Cyber Dashboard

A comprehensive security monitoring dashboard combining InfluxDB, Telegraf, and Grafana for real-time infrastructure and security event monitoring.

## Features

- **Real-time Security Monitoring** - Track failed login attempts, intrusion detection alerts, and firewall actions
- **System Metrics** - Monitor CPU, memory, disk usage, and process activity
- **Network Monitoring** - Capture and visualize web server access logs (Nginx, Apache)
- **Multi-bucket Data Organization** - Separate buckets for different data types (security_logs, network_logs, intrusion_detection, system_metrics)
- **Automated Dashboard Provisioning** - Pre-built Grafana dashboards with Flux queries
- **Docker Compose Setup** - Simple deployment with docker-compose

## Quick Start

### Prerequisites

- Docker & Docker Compose installed
- Port 3000 (Grafana), 8087 (InfluxDB) available
- 2GB+ free disk space

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/danhub-co/cyber-dahsboard.git
   cd cyber-dashboard
   ```

2. **Set up environment variables:**
   ```bash
   # Option 1: Use automated setup (recommended)
   ./setup.sh
   
   # Option 2: Manual setup
   cp .env.example .env
   # Edit .env and set secure passwords
   ```

3. **Start all services:**
   ```bash
   docker-compose up -d
   ```

4. **Verify services are running:**
   ```bash
   docker-compose ps
   ```

   Expected output:
   ```
   NAME                      COMMAND                  STATE                    PORTS
   cyber-dashboard_grafana_1    /run.sh                Up      0.0.0.0:3000->3000/tcp
   cyber-dashboard_influxdb_1   /entrypoint.sh influxd Up      0.0.0.0:8087->8087/tcp
   cyber-dashboard_telegraf_1   /entrypoint.sh telegraf Up      8092/udp, 8094/tcp, 8125/udp
   ```

### Access the Dashboard

- **URL:** http://localhost:3000
- **Username:** Check your `.env` file (default: `admin`)
- **Password:** Generated during setup (check `.env` file)

⚠️ **Security Note:** Default credentials are auto-generated. See [SECURITY.md](SECURITY.md) for production hardening.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Telegraf  │────▶│   InfluxDB   │────▶│   Grafana   │
│  (Collector)│     │ (Time-Series)│     │ (Visualize) │
└─────────────┘     └──────────────┘     └─────────────┘
      │
      ├─ /var/log/auth.log (Failed logins)
      ├─ /var/log/fail2ban.log (Intrusions)
      ├─ /var/log/nginx/access.log (Web traffic)
      ├─ /var/log/apache2/access.log (Web traffic)
      └─ System metrics (CPU, Memory, Disk)
```

## Data Flow

### Data Sources → Telegraf → InfluxDB Buckets

| Data Source | Bucket | Description |
|---|---|---|
| `/var/log/auth.log` | security_logs | Failed SSH login attempts |
| `/var/log/fail2ban.log` | intrusion_detection | Fail2Ban firewall blocks |
| `/var/log/nginx/access.log` | network_logs | Nginx web server access logs |
| `/var/log/apache2/access.log` | network_logs | Apache web server access logs |
| CPU, Memory, Disk | system_metrics | System performance metrics |

## InfluxDB Configuration

### Organization
- **Name:** `my-org`
- **ID:** `a056c5c6bf3169f6`
- **Admin User:** `admin`
- **Password:** `password12345`

### Buckets
1. **security_logs** - Failed login attempts and authentication events
2. **network_logs** - Web server access logs
3. **intrusion_detection** - IDS/IPS alerts and Fail2Ban actions
4. **system_metrics** - CPU, memory, disk, process metrics
5. **_monitoring** - System monitoring (auto-created)
6. **_tasks** - Task storage (auto-created)

### Authentication
- **Token:** `my-super-secret-auth-token`
- **URL:** `http://localhost:8087`
- **API Endpoint:** `http://localhost:8087/api/v2`

## Grafana Dashboards

### Security Overview Dashboard

**Panels:**
1. **Failed Login Attempts** (Last 1 hour) - Gauge showing count
2. **Fail2Ban Actions** (Last 1 hour) - Gauge showing intrusion blocks
3. **CPU Usage (Latest)** - Pie chart
4. **CPU Usage Over Time** - Line chart (1-hour window)
5. **Memory Usage Over Time** - Line chart (1-hour window)
6. **Disk Usage Over Time** - Line chart (1-hour window)

**Auto-refresh:** 30 seconds

**Queries Use Flux Language:**
```flux
from(bucket:"security_logs")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "failed_logins")
  |> count()
```

## Telegraf Configuration

### Input Plugins

**Log Parsing (Grok format):**
- `inputs.tail` - Parse auth.log, fail2ban.log, and web server logs

**System Metrics:**
- `inputs.cpu` - CPU usage per core and total
- `inputs.disk` - Disk I/O and usage statistics
- `inputs.mem` - Memory usage
- `inputs.processes` - Running process count

### Output Configuration

**Multi-bucket routing** via tag-based filtering:
```toml
[[outputs.influxdb_v2]]
  urls = ["http://influxdb:8086"]
  token = "my-super-secret-auth-token"
  organization = "my-org"
  bucket = "security_logs"
  [outputs.influxdb_v2.tagpass]
    bucket = ["security_logs"]
```

## Common Tasks

### View InfluxDB Buckets

```bash
docker-compose exec -T influxdb influx bucket list \
  --org-id a056c5c6bf3169f6 \
  --token my-super-secret-auth-token
```

### Query Data via InfluxDB CLI

```bash
docker-compose exec -T influxdb influx query \
  'from(bucket:"security_logs") |> range(start: -1h) |> limit(n: 10)' \
  --token my-super-secret-auth-token \
  --org my-org
```

### Check Telegraf Logs

```bash
docker-compose logs -f telegraf
```

### Check InfluxDB Logs

```bash
docker-compose logs -f influxdb
```

### Restart All Services

```bash
docker-compose restart
```

### Stop All Services

```bash
docker-compose down
```

### Stop and Remove Data

```bash
docker-compose down -v
```

## File Structure

```
cyber-dashboard/
├── docker-compose.yml                 # Docker services definition
├── telegraf.conf                      # Telegraf configuration
├── grafana-datasource.yml             # InfluxDB datasource config
├── grafana-dashboard-provisioner.yml  # Dashboard auto-provisioning
├── grafana-dashboards/
│   ├── dashboards.yaml               # Provisioning config file
│   └── security-overview.json        # Security dashboard definition
├── fail2ban/
│   └── jail.d/
│       └── sshd.conf                 # Fail2Ban SSH jail config
└── README.md                         # This file
```

## Environment Variables

All credentials are managed via `.env` file. See `.env.example` for template.

**Quick setup:**
```bash
./setup.sh  # Generates secure credentials automatically
```

**Manual configuration:**
- `INFLUXDB_USERNAME` - InfluxDB admin username
- `INFLUXDB_PASSWORD` - InfluxDB admin password (min 8 chars)
- `INFLUXDB_TOKEN` - InfluxDB authentication token
- `GRAFANA_ADMIN_USER` - Grafana admin username
- `GRAFANA_ADMIN_PASSWORD` - Grafana admin password

📖 See [SECURITY.md](SECURITY.md) for production deployment guide.

## Security Considerations

⚠️ **Important:** This setup is for development/testing. For production:

1. **Change default passwords** in both InfluxDB and Grafana
2. **Use strong authentication tokens** for InfluxDB
3. **Enable HTTPS/TLS** for all services
4. **Use secrets management** (Docker Secrets, Vault, etc.)
5. **Restrict network access** with firewall rules
6. **Set data retention policies** to manage storage
7. **Enable audit logging** for compliance
8. **Use persistent volumes** for data backup

## Troubleshooting

### Services fail to start

```bash
# Full system cleanup
docker-compose down -v
docker system prune -af
docker-compose up -d
```

### No data appearing in Grafana

1. **Check Telegraf logs:**
   ```bash
   docker-compose logs telegraf | tail -20
   ```

2. **Verify InfluxDB connectivity:**
   ```bash
   docker-compose exec -T telegraf curl -v http://influxdb:8086/api/v2/setup
   ```

3. **Check datasource in Grafana:**
   - Settings → Data Sources → InfluxDB
   - Click "Test" to verify connection

### Grafana login fails

```bash
# Reset Grafana database
docker-compose down grafana
docker volume rm cyber-dashboard_grafana-data
docker-compose up -d grafana
```

### InfluxDB Connection Refused

Ensure port 8087 is not already in use:
```bash
lsof -i :8087
# or
netstat -tlnp | grep 8087
```

## Performance Tuning

### Telegraf Interval
Edit `telegraf.conf` to adjust collection interval:
```toml
[agent]
  interval = "10s"        # Default: 10 seconds
  flush_interval = "10s"
```

### InfluxDB Retention
Set retention policy per bucket:
```bash
docker-compose exec -T influxdb influx bucket update \
  --name security_logs \
  --retention 30d \  # Keep data for 30 days
  --token my-super-secret-auth-token \
  --org my-org
```

### Grafana Dashboard Refresh
Adjust in dashboard settings or use annotation:
```json
"refresh": "15s"  // Update every 15 seconds
```

## Integration Examples

### Adding Custom Metrics

1. **Install Telegraf plugin** (e.g., MySQL monitoring)
2. **Update telegraf.conf:**
   ```toml
   [[inputs.mysql]]
     servers = ["root:password@tcp(localhost:3306)/"]
     [inputs.mysql.tags]
       bucket = "system_metrics"
   ```
3. **Restart Telegraf:**
   ```bash
   docker-compose restart telegraf
   ```

### Exporting Dashboard

```bash
# Export as JSON (backup)
curl -s -u admin:Admin123456 \
  http://localhost:3000/api/dashboards/uid/security-overview \
  | jq '.dashboard' > backup-dashboard.json
```

## Support & Documentation

- **InfluxDB Docs:** https://docs.influxdata.com/influxdb/latest/
- **Telegraf Docs:** https://docs.influxdata.com/telegraf/latest/
- **Grafana Docs:** https://grafana.com/docs/grafana/latest/
- **GitHub Issues:** https://github.com/danhub-co/cyber-dahsboard/issues

## License

This project is provided as-is for security monitoring and educational purposes.

## Changelog

### v1.0 (2026-02-16)
- Initial release with InfluxDB, Telegraf, and Grafana
- Multi-bucket data organization
- Security Overview dashboard
- Automated provisioning
- Fail2Ban integration

---

**Last Updated:** February 16, 2026  
**Version:** 1.0  
**Status:** Stable
