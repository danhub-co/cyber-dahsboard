# InfluxDB and Grafana Alert Configuration Guide

## Overview
This document outlines the security event alert system for the cyber-dashboard, including:
- Alert rules for failed logins, intrusions, and performance issues
- Notification channels (webhook, email)
- Alert thresholds and evaluation intervals
- Best practices for alert management

## Alert Rules Configuration

### 1. Failed Login Attempts Alert
**Trigger Condition**: More than 10 failed login attempts in 10 minutes
**Severity**: HIGH
**Notification**: Webhook + Email

```yaml
Rule: failed-logins-alert
Metric: security_logs bucket - failed_logins measurement
Query: Count failed login events in last 10 minutes
Threshold: > 10
Duration: 5 minutes (time before alerting)
Labels:
  - severity: high
  - team: security
```

### 2. Intrusion Detection Alert
**Trigger Condition**: Any IP address banned by Fail2Ban
**Severity**: CRITICAL
**Notification**: Webhook + Email

```yaml
Rule: intrusion-detection-alert
Metric: intrusion_detection bucket - fail2ban_actions measurement
Query: Count ban actions in last 5 minutes
Threshold: > 0 (any ban action)
Duration: 1 minute
Labels:
  - severity: critical
  - team: security
```

### 3. HTTP Error Rate Alert
**Trigger Condition**: 50+ HTTP 5xx errors in 5 minutes
**Severity**: HIGH
**Notification**: Webhook + Email

```yaml
Rule: http-error-alert
Metric: network_logs bucket - nginx_access/apache_access measurements
Query: Count HTTP 5xx errors in last 5 minutes
Threshold: > 50
Duration: 5 minutes
Labels:
  - severity: high
  - team: devops
```

### 4. High CPU Usage Alert
**Trigger Condition**: CPU usage > 80% for 5 minutes
**Severity**: MEDIUM
**Notification**: Webhook

```yaml
Rule: system-load-alert
Metric: system_metrics bucket - cpu measurement
Query: Average CPU usage in last 5 minutes
Threshold: > 80%
Duration: 5 minutes
Labels:
  - severity: medium
  - team: infrastructure
```

## Notification Channels

### Webhook Channel
- **URL**: http://localhost:5000/alerts (configurable)
- **Method**: POST
- **Use Case**: Custom alerting, SOAR integration, ticketing systems
- **Example Receivers**: 
  - Slack webhooks
  - PagerDuty
  - Custom Python/Node.js webhook handlers
  - Elasticsearch alerts

### Email Channel
- **Recipients**: security@example.com (update with real addresses)
- **Use Case**: Immediate notification to security team
- **Configuration**: Requires Grafana SMTP settings

## Setting Up Alert Notifications

### 1. Run the Alert Setup Script
```bash
bash setup-alerts.sh
```

This will:
- Create notification channels (webhook, email)
- Configure 4 alert rules
- Set appropriate thresholds and evaluation intervals

### 2. Configure Email Alerts (Optional)
Edit `docker-compose.yml` Grafana environment:
```yaml
environment:
  GF_SMTP_ENABLED: "true"
  GF_SMTP_HOST: "smtp.gmail.com:587"
  GF_SMTP_USER: "your-email@gmail.com"
  GF_SMTP_PASSWORD: "your-app-password"
  GF_SMTP_FROM_ADDRESS: "security-alerts@example.com"
```

Then restart Grafana:
```bash
docker-compose restart grafana
```

### 3. Configure Webhook Alerts
Create a simple webhook receiver:

```python
# webhook-receiver.py
from flask import Flask, request
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/alerts', methods=['POST'])
def receive_alert():
    alert = request.json
    
    # Log alert
    with open('alerts.log', 'a') as f:
        f.write(f"[{datetime.now()}] {json.dumps(alert, indent=2)}\n")
    
    # Process based on severity
    severity = alert.get('commonLabels', {}).get('severity', 'unknown')
    title = alert.get('groupLabels', {}).get('alertname', 'Unknown Alert')
    
    if severity == 'critical':
        # Send urgent notification
        send_critical_alert(title, alert)
    
    return {"status": "received"}, 200

def send_critical_alert(title, alert):
    # Send to Slack, PagerDuty, etc.
    print(f"🚨 CRITICAL ALERT: {title}")
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

Run webhook receiver:
```bash
pip install flask
python webhook-receiver.py
```

## Alert Management

### View Active Alerts
```bash
# In Grafana UI: Click "Alerts" in sidebar
# Or via API:
curl -u admin:Admin123456 http://localhost:3000/api/v1/rules
```

### Modify Alert Rules
1. Go to Grafana > Alerts > Alert Rules
2. Click the alert you want to modify
3. Update threshold, duration, or conditions
4. Save changes

### Silence Alerts (Maintenance Window)
```bash
# Via API:
curl -u admin:Admin123456 -X POST \
  http://localhost:3000/api/v1/admin/pause-all-alerts \
  -H "Content-Type: application/json" \
  -d '{"paused": true}'
```

### Test Alert Rules
Trigger a test by manually increasing metric values:
```bash
# Example: Add test failed login entry
docker-compose exec -T influxdb influx write \
  --bucket security_logs \
  --org my-org \
  --token my-super-secret-auth-token \
  'failed_logins,user=testuser value=1'
```

## Alert Dashboard
Create a dedicated dashboard to visualize alert history:

1. **Panel 1**: Alert Firing Status (Stat panel)
2. **Panel 2**: Alerts by Severity (Pie chart)
3. **Panel 3**: Alert Firing Timeline (Time series)
4. **Panel 4**: Alert Documentation (Text panel)

```json
// Example Flux Query for Alert Timeline
from(bucket: "system_metrics")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "alert_events")
  |> group(by: ["alertname", "severity"])
  |> count()
```

## Common Alert Thresholds (Recommended)

| Alert | Threshold | Duration | Severity |
|-------|-----------|----------|----------|
| Failed Logins | > 10/10min | 5 min | HIGH |
| Intrusions | > 0/5min | 1 min | CRITICAL |
| HTTP 5xx | > 50/5min | 5 min | HIGH |
| CPU Usage | > 80% | 5 min | MEDIUM |
| Memory Usage | > 90% | 10 min | HIGH |
| Disk Usage | > 95% | 15 min | CRITICAL |

## Troubleshooting Alerts

### Alerts Not Firing
1. Check if alert rule is enabled: `curl -u admin:Admin123456 http://localhost:3000/api/v1/rules`
2. Verify datasource connectivity: Click "Test Query" in alert rule
3. Check Grafana logs: `docker-compose logs grafana`

### Notification Not Sending
1. Verify notification channel: Grafana > Notifications
2. For Email: Check SMTP settings and credentials
3. For Webhook: Test endpoint with: `curl -X POST http://localhost:5000/alerts -d '{"test": "data"}'`

### High False Positive Rate
1. Increase evaluation duration (5m → 10m)
2. Increase threshold (10 → 15 failed logins)
3. Add condition filters (only certain users, IPs)

## Integration Examples

### Slack Integration
```bash
# In Grafana Notifications, add Slack webhook:
https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### PagerDuty Integration
```bash
# In Grafana Notifications, add PagerDuty:
Type: pagerduty
Integration Key: xxxxxxxxxxxxx
```

### Elasticsearch Logging
Configure webhook to send alerts to Elasticsearch for long-term storage:
```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

def log_to_elasticsearch(alert):
    es.index(index='security-alerts', body=alert)
```

## Next Steps
1. ✅ Run `bash setup-alerts.sh` to create base alerts
2. ⬜ Update email addresses in notification channels
3. ⬜ Configure SMTP for email delivery
4. ⬜ Set up webhook receiver for critical alerts
5. ⬜ Create alert acknowledgment/escalation workflow
6. ⬜ Document runbooks for each alert rule
7. ⬜ Set up alert dashboard for monitoring alert health

