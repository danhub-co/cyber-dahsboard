# Alert Setup and Integration Guide

This guide covers the complete setup and management of security alerts in the cyber-dashboard.

## Quick Start

### 1. Update Docker Compose and Start Services

The webhook receiver service has been added to the docker-compose.yml. Start all services:

```bash
cd /home/ubuntu26/cyber-dashboard
docker-compose up -d
```

Verify all services are running:

```bash
docker-compose ps
```

Expected output:
```
NAME               STATUS
cyber-dashboard-influxdb-1      Up
cyber-dashboard-telegraf-1      Up
cyber-dashboard-grafana-1       Up
cyber-dashboard-webhook-receiver-1   Up
```

### 2. Configure Grafana Alerts

Run the alert setup script to create alert rules and notification channels:

```bash
bash setup-alerts.sh
```

This creates:
- ✅ Webhook notification channel (http://webhook-receiver:5000/alerts)
- ✅ Email notification channel (template - requires SMTP config)
- ✅ 4 alert rules (Failed Logins, Intrusions, HTTP Errors, CPU Usage)

### 3. Verify Webhook Receiver Connectivity

Test the webhook receiver is working:

```bash
# Check service health
curl http://localhost:5000/health

# Check alert statistics
curl http://localhost:5000/stats

# View alert history
curl http://localhost:5000/alerts-history?limit=10
```

Expected responses:
```json
{"status": "healthy", "timestamp": "2024-02-16T..."}
{"total": 0, "by_severity": {}, "by_name": {}, "recent": []}
[]
```

## Alert Configuration Details

### Grafana Unified Alerting

The webhook receiver integrates with Grafana's alerting system:

1. **Alert Rules**: Define conditions that trigger alerts
2. **Notification Channels**: Define where alerts are sent
3. **Contact Points**: Recipients of alerts (email, webhook, etc.)
4. **Alert Groups**: Organize and batch similar alerts

### How Alerts Flow

```
Security Event Detected
    ↓
Telegraf collects metrics/logs
    ↓
Data written to InfluxDB buckets
    ↓
Grafana alert rule evaluates query
    ↓
Threshold exceeded
    ↓
Alert fires
    ↓
Notification channel sends to webhook-receiver
    ↓
Webhook receiver processes and logs alert
    ↓
Actions taken (logging, integration, escalation)
```

## Webhook Receiver Endpoints

### POST /alerts
Main endpoint for receiving Grafana alerts

```bash
curl -X POST http://localhost:5000/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "status": "firing",
    "groupLabels": {"alertname": "test_alert"},
    "commonLabels": {"severity": "high"},
    "commonAnnotations": {"description": "Test alert"}
  }'
```

Response:
```json
{
  "status": "processed",
  "alert_name": "test_alert",
  "severity": "high",
  "timestamp": "2024-02-16T..."
}
```

### GET /health
Health check endpoint

```bash
curl http://localhost:5000/health
```

### GET /stats
Alert statistics

```bash
curl http://localhost:5000/stats
```

Response:
```json
{
  "total": 5,
  "by_severity": {"critical": 2, "high": 2, "medium": 1},
  "by_name": {"failed-logins-alert": 3, ...},
  "recent": [...]
}
```

### GET /alerts-history
View alert history with optional limit

```bash
curl "http://localhost:5000/alerts-history?limit=20"
```

### GET /alerts/<severity>
Filter alerts by severity level

```bash
curl http://localhost:5000/alerts/critical
curl http://localhost:5000/alerts/high
curl http://localhost:5000/alerts/medium
```

## Email Alert Configuration

To enable email alerts from Grafana:

### 1. Add SMTP Environment Variables

Edit `docker-compose.yml` and add to Grafana environment:

```yaml
grafana:
  environment:
    - GF_SMTP_ENABLED=true
    - GF_SMTP_HOST=smtp.gmail.com:587
    - GF_SMTP_USER=your-email@gmail.com
    - GF_SMTP_PASSWORD=your-app-password
    - GF_SMTP_FROM_ADDRESS=security-alerts@example.com
    - GF_SMTP_FROM_NAME=Cyber Dashboard
    - GF_SMTP_SKIP_VERIFY=true
```

### 2. Restart Grafana

```bash
docker-compose restart grafana
```

### 3. Update Email Channel in Grafana UI

1. Go to Grafana > Notifications
2. Edit "Security Email Alerts" channel
3. Update email addresses for your team
4. Test the connection

## Advanced Alert Rules

### Creating Custom Alert Rules via Grafana UI

1. Navigate to **Alerts > Alert Rules > New Alert Rule**
2. Configure:
   - **Data source**: InfluxDB
   - **Query**: Write Flux query to fetch data
   - **Condition**: Define threshold (e.g., `> 10`)
   - **For**: Duration before alerting (e.g., `5m`)
   - **Annotations**: Add description and runbook links
   - **Labels**: Add tags for routing (e.g., `severity: high`)

### Example: Custom Query Alert

Alert when failed logins spike:

```flux
from(bucket: "security_logs")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "failed_logins")
  |> group(by: ["user"])
  |> count()
  |> filter(fn: (r) => r._value > 5)
```

Then set threshold `> 0` to alert if any user has >5 failed attempts.

## Integrating with External Services

### Slack Integration

1. Create Slack Incoming Webhook: https://api.slack.com/messaging/webhooks
2. In Grafana, add new Notification Channel:
   - Type: Incoming webhook
   - URL: `https://hooks.slack.com/services/YOUR/WEBHOOK/URL`
   - Enable: "Send on resolve"

### PagerDuty Integration

1. Get PagerDuty Integration Key from your project
2. In Grafana, add new Notification Channel:
   - Type: PagerDuty
   - Integration Key: `YOUR_KEY`
   - Severity mapping: Critical = warning

### Custom Webhook Handler

Create custom alert handler by modifying `webhook-receiver.py`:

```python
def send_to_slack(alert_data):
    """Send alert to Slack"""
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK"
    message = {
        "text": f"🚨 {alert_data['name']} [Severity: {alert_data['severity']}]",
        "blocks": [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Alert Fired*\n" + str(alert_data)}
        }]
    }
    requests.post(webhook_url, json=message)

def send_to_pagerduty(alert_data):
    """Send alert to PagerDuty"""
    endpoint = "https://events.pagerduty.com/v2/enqueue"
    event = {
        "routing_key": "YOUR_ROUTING_KEY",
        "event_action": "trigger",
        "payload": {
            "summary": f"{alert_data['name']} - {alert_data['severity']}",
            "severity": map_severity(alert_data['severity']),
            "source": "Cyber Dashboard"
        }
    }
    requests.post(endpoint, json=event)
```

## Alert Dashboards

Create a dashboard to monitor alert health:

### Panel 1: Alert Firing Status
```flux
from(bucket: "system_metrics")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "alerts_fired")
  |> last()
  |> group(by: ["alert_name"])
  |> count()
```

### Panel 2: Alerts by Severity
```flux
from(bucket: "system_metrics")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "alerts_fired")
  |> group(by: ["severity"])
  |> count()
```

### Panel 3: Mean Time to Resolution (MTTR)
```flux
from(bucket: "system_metrics")
  |> range(start: -30d)
  |> filter(fn: (r) => r._measurement == "alert_resolution_time")
  |> mean()
```

## Troubleshooting Alerts

### Alerts Not Firing

1. **Check alert rule is enabled**:
   ```bash
   curl -u admin:Admin123456 http://localhost:3000/api/v1/rules
   ```

2. **Verify query in alert rule**:
   - Click "Test Query" in Grafana alert rule editor
   - Check for data returned in time range

3. **Check Grafana logs**:
   ```bash
   docker-compose logs grafana | tail -50
   ```

4. **Verify datasource connectivity**:
   - Go to Grafana > Configuration > Data Sources
   - Click InfluxDB datasource > "Test"

### Webhook Receiver Not Receiving Alerts

1. **Check service is running**:
   ```bash
   docker-compose ps webhook-receiver
   docker-compose logs webhook-receiver
   ```

2. **Test webhook endpoint**:
   ```bash
   curl -X POST http://localhost:5000/alerts \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}'
   ```

3. **Check notification channel configuration**:
   - Grafana > Notifications > Check URL is correct
   - Should be: `http://webhook-receiver:5000/alerts`

### High False Positive Rate

1. **Increase evaluation duration**:
   - Change alert "For" field from 5m to 10m or 15m

2. **Increase threshold**:
   - Failed logins: 10 → 20 attempts
   - CPU usage: 80% → 85%

3. **Add condition filters**:
   ```flux
   |> filter(fn: (r) => r.user != "system")
   |> filter(fn: (r) => r.severity == "critical")
   ```

## Alert Testing

### Manually Trigger Alert Conditions

#### Test Failed Login Alert
```bash
docker-compose exec -T influxdb influx write \
  --bucket security_logs \
  --org my-org \
  --token my-super-secret-auth-token \
  "failed_logins,user=testuser value=1"
```

Repeat 10+ times within 10 minutes to trigger alert.

#### Test Intrusion Alert
```bash
docker-compose exec -T influxdb influx write \
  --bucket intrusion_detection \
  --org my-org \
  --token my-super-secret-auth-token \
  "fail2ban_actions,ip=192.168.1.100,action=Ban jail=sshd value=1"
```

#### Monitor Webhook Receiver Logs
```bash
docker-compose logs -f webhook-receiver
```

Watch for incoming alert processing.

## Production Hardening

### Security Checklist

- [ ] Change default Grafana admin password
- [ ] Change InfluxDB admin password
- [ ] Enable HTTPS for Grafana
- [ ] Configure SMTP with proper credentials
- [ ] Monitor alert fatigue (% of acknowledged vs total)
- [ ] Implement alert suppression rules
- [ ] Set up alert escalation policies
- [ ] Enable audit logging
- [ ] Regular backup of alert configurations
- [ ] Test alert channels weekly

### Performance Optimization

- Set reasonable evaluation intervals (min 1m)
- Archive old alerts to reduce query load
- Use downsampling for long-term alert data
- Implement alert aggregation for similar events

## Maintenance

### Weekly Tasks
- Review alert statistics: `curl http://localhost:5000/stats`
- Check false positive rate
- Verify notification channels are working
- Review recent alerts for patterns

### Monthly Tasks
- Adjust alert thresholds based on baseline trends
- Review and update runbook links
- Clean up inactive alert rules
- Update team contact information

### Quarterly Tasks
- Audit alert performance (MTTR, false positive %)
- Review alert coverage vs security threats
- Update alert rules for new attack vectors
- Test disaster recovery procedures

## References

- [Grafana Alerting Documentation](https://grafana.com/docs/grafana/latest/alerting/)
- [InfluxDB Alerts](https://docs.influxdata.com/influxdb/v2/process-data/manage-tasks/create-task/)
- [Webhook-Receiver API Documentation](./webhook-receiver.py)
- [Alert Rules Configuration](./ALERTS.md)

