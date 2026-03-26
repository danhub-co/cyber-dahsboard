# Security Alert Runbooks

Response procedures for each alert type in the Cyber Dashboard.

---

## RB-01 — High Failed Login Attempts

**Alert:** `failed-logins-alert`
**Severity:** High
**Trigger:** >10 failed login attempts in 10 minutes
**Notifies:** Webhook + Email → `daniotest4@gmail.com`

### Triage (< 2 minutes)

1. Check the alert details in Grafana → **Alerts → Alert Rules → High Failed Login Attempts**
2. Query the affected accounts:
   ```bash
   docker compose exec -T influxdb influx query \
     'from(bucket:"security_logs") |> range(start: -15m)
      |> filter(fn: (r) => r._measurement == "failed_logins")
      |> group(columns: ["user"])
      |> count()
      |> sort(columns: ["_value"], desc: true)' \
     --token $INFLUXDB_TOKEN --org my-org
   ```
3. Check source IPs on the host:
   ```bash
   grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20
   ```

### Containment

4. If brute-force confirmed, block the source IP immediately:
   ```bash
   sudo fail2ban-client set sshd banip <source-ip>
   ```
5. Lock the targeted account if compromised:
   ```bash
   sudo passwd -l <username>
   ```
6. Check if any login succeeded after the failed attempts:
   ```bash
   grep "Accepted password" /var/log/auth.log | grep <username>
   ```

### Investigation

7. Identify attack pattern — single IP or distributed?
   ```bash
   grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort -u | wc -l
   ```
8. Check if targeted usernames are valid system accounts:
   ```bash
   grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn
   ```
9. Review active sessions for any suspicious logins:
   ```bash
   who
   last | head -20
   ```

### Recovery

10. If no successful login — increase fail2ban threshold if false positive rate is high:
    ```bash
    # Edit /etc/fail2ban/jail.d/sshd.conf
    # Increase maxretry from 5 to 10
    sudo fail2ban-client reload
    ```
11. If successful login detected — treat as **active incident**, escalate immediately.

### Acknowledge

```bash
curl -X POST http://localhost:5000/alerts/<alert-id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"note": "Investigated - source IP blocked, no successful logins confirmed"}'
```

### Escalation Triggers
- Any successful login after failed attempts → **Incident Response**
- >100 attempts from distributed IPs → **DDoS/Credential Stuffing**
- Targeted admin/root accounts → **Privilege Escalation Attempt**

---

## RB-02 — Intrusion Detected (IP Banned by Fail2Ban)

**Alert:** `intrusion-detection-alert`
**Severity:** Critical
**Trigger:** Any IP banned by Fail2Ban in last 5 minutes
**Notifies:** Webhook + Email → `daniotest4@gmail.com`

### Triage (< 1 minute)

1. Get the banned IP from InfluxDB:
   ```bash
   docker compose exec -T influxdb influx query \
     'from(bucket:"intrusion_detection") |> range(start: -10m)
      |> filter(fn: (r) => r._measurement == "fail2ban_actions" and r.action == "Ban")
      |> keep(columns: ["_time", "ip", "jail"])' \
     --token $INFLUXDB_TOKEN --org my-org
   ```
2. Check Fail2Ban logs directly:
   ```bash
   sudo tail -50 /var/log/fail2ban.log | grep "Ban"
   ```
3. Verify the ban is active:
   ```bash
   sudo fail2ban-client status sshd
   ```

### Containment

4. Confirm the IP is still banned:
   ```bash
   sudo iptables -L -n | grep <banned-ip>
   ```
5. If the IP is known malicious, add to permanent blocklist:
   ```bash
   sudo iptables -I INPUT -s <banned-ip> -j DROP
   sudo iptables-save > /etc/iptables/rules.v4
   ```
6. Check if the IP is hitting other services:
   ```bash
   sudo grep <banned-ip> /var/log/nginx/access.log | tail -20
   sudo grep <banned-ip> /var/log/apache2/access.log 2>/dev/null | tail -20
   ```

### Investigation

7. Look up the IP reputation:
   - Check: https://www.abuseipdb.com/check/<banned-ip>
   - Check: https://www.virustotal.com/gui/ip-address/<banned-ip>
8. Identify attack type from logs:
   ```bash
   sudo grep <banned-ip> /var/log/auth.log | tail -30
   ```
9. Check for lateral movement — did the IP reach any other hosts?
   ```bash
   sudo grep <banned-ip> /var/log/syslog | tail -20
   ```

### Recovery

10. If false positive (known IP, e.g. monitoring system):
    ```bash
    sudo fail2ban-client set sshd unbanip <banned-ip>
    # Add to ignoreip in /etc/fail2ban/jail.d/sshd.conf
    ```
11. If confirmed malicious — report to upstream ISP/provider if persistent.

### Acknowledge

```bash
curl -X POST http://localhost:5000/alerts/<alert-id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"note": "IP <banned-ip> confirmed malicious - permanently blocked, reported to AbuseIPDB"}'
```

### Escalation Triggers
- Same IP unbanned and re-banned within 1 hour → **Persistent Attacker**
- Multiple IPs from same subnet → **Coordinated Attack**
- Ban on non-SSH service (HTTP, FTP) → **Multi-vector Attack**

---

## RB-03 — High HTTP Error Rate

**Alert:** `http-error-alert`
**Severity:** High
**Trigger:** >50 HTTP 5xx errors in 5 minutes
**Notifies:** Webhook + Email → `daniotest4@gmail.com`

### Triage (< 2 minutes)

1. Check current error rate in InfluxDB:
   ```bash
   docker compose exec -T influxdb influx query \
     'from(bucket:"network_logs") |> range(start: -10m)
      |> filter(fn: (r) => r._measurement =~ /nginx_access|apache_access/)
      |> group(columns: ["http_code"])
      |> count()' \
     --token $INFLUXDB_TOKEN --org my-org
   ```
2. Check web server error logs:
   ```bash
   sudo tail -100 /var/log/nginx/error.log
   sudo tail -100 /var/log/apache2/error.log 2>/dev/null
   ```
3. Check if the service is still responding:
   ```bash
   curl -o /dev/null -s -w "%{http_code}" http://localhost
   ```

### Containment

4. Check backend application status:
   ```bash
   docker compose ps
   systemctl status <app-service>
   ```
5. Check database connectivity if applicable:
   ```bash
   docker compose exec -T influxdb influx ping --host http://localhost:8086
   ```
6. Check disk space — full disk causes 500 errors:
   ```bash
   df -h
   ```
7. Check memory — OOM kills cause 502/503:
   ```bash
   free -h
   dmesg | grep -i "oom" | tail -10
   ```

### Investigation

8. Identify which endpoints are failing:
   ```bash
   sudo grep " 5[0-9][0-9] " /var/log/nginx/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20
   ```
9. Check if it's a spike (DDoS) or sustained (application bug):
   ```bash
   sudo grep " 5[0-9][0-9] " /var/log/nginx/access.log | awk '{print $4}' | cut -d: -f2 | sort | uniq -c
   ```
10. Check source IPs for DDoS pattern:
    ```bash
    sudo grep " 5[0-9][0-9] " /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
    ```

### Recovery

11. If application crash — restart the service:
    ```bash
    docker compose restart <service-name>
    ```
12. If DDoS — enable rate limiting in Nginx:
    ```nginx
    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
    limit_req zone=one burst=20 nodelay;
    ```
13. If disk full — clean up logs:
    ```bash
    sudo journalctl --vacuum-size=500M
    docker system prune -f
    ```

### Acknowledge

```bash
curl -X POST http://localhost:5000/alerts/<alert-id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"note": "Root cause: <cause> - resolved by <action>"}'
```

### Escalation Triggers
- Error rate >500/5min → **Service Outage**
- Errors from single IP >1000/min → **DDoS Attack**
- Errors persist after restart → **Application Bug / Data Corruption**

---

## RB-04 — High CPU Usage

**Alert:** `system-load-alert`
**Severity:** Medium
**Trigger:** CPU usage >80% for 5 minutes
**Notifies:** Webhook only

### Triage (< 5 minutes)

1. Check current CPU usage:
   ```bash
   docker compose exec -T influxdb influx query \
     'from(bucket:"system_metrics") |> range(start: -10m)
      |> filter(fn: (r) => r._measurement == "cpu" and r._field == "usage_system")
      |> aggregateWindow(every: 1m, fn: mean)' \
     --token $INFLUXDB_TOKEN --org my-org
   ```
2. Identify top CPU consumers on the host:
   ```bash
   ps aux --sort=-%cpu | head -15
   ```
3. Check if it's a container causing the spike:
   ```bash
   docker stats --no-stream
   ```

### Containment

4. Check for runaway processes:
   ```bash
   top -b -n1 | head -20
   ```
5. Check for crypto mining or malicious processes:
   ```bash
   ps aux | grep -E "xmrig|minerd|cryptonight" 
   ls -la /proc/*/exe 2>/dev/null | grep deleted
   ```
6. Check system load average trend:
   ```bash
   uptime
   sar -u 1 5 2>/dev/null || vmstat 1 5
   ```

### Investigation

7. Check if CPU spike correlates with a deployment or cron job:
   ```bash
   sudo grep "$(date +%H:%M)" /var/log/syslog | tail -20
   crontab -l
   sudo crontab -l
   ```
8. Check for memory pressure causing CPU thrashing:
   ```bash
   vmstat 1 5
   free -h
   ```
9. Check InfluxDB and Telegraf resource usage:
   ```bash
   docker stats cyber-dashboard-influxdb-1 cyber-dashboard-telegraf-1 --no-stream
   ```

### Recovery

10. If a specific process is runaway — kill it:
    ```bash
    sudo kill -15 <pid>
    # If unresponsive:
    sudo kill -9 <pid>
    ```
11. If a Docker container is consuming too much — restart it:
    ```bash
    docker compose restart <service>
    ```
12. If sustained high CPU with no clear cause — reboot as last resort:
    ```bash
    docker compose down
    sudo reboot
    docker compose up -d
    ```

### Acknowledge

```bash
curl -X POST http://localhost:5000/alerts/<alert-id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"note": "Root cause: <process/service> - resolved by <action>"}'
```

### Escalation Triggers
- CPU >95% for >15 minutes → **Service Degradation**
- Unknown process consuming CPU → **Possible Cryptominer / Malware**
- CPU spike after new deployment → **Performance Regression**

---

## Quick Reference

| Alert | Severity | First Action | Acknowledge SLA |
|-------|----------|-------------|-----------------|
| Failed Logins | High | Check source IPs, block if brute-force | 15 minutes |
| Intrusion Detected | Critical | Verify ban, check lateral movement | 5 minutes |
| High HTTP Errors | High | Check service status and logs | 15 minutes |
| High CPU Usage | Medium | Identify top process, check for malware | 30 minutes |

## Useful Commands

```bash
# View all pending alerts
curl http://localhost:5000/alerts/pending | jq '[.[] | {id, name, severity, timestamp}]'

# View critical alerts only
curl http://localhost:5000/alerts/severity/critical | jq '[.[] | {id, name, acknowledged}]'

# Acknowledge an alert
curl -X POST http://localhost:5000/alerts/<id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"note": "<your note>"}'

# Alert statistics
curl http://localhost:5000/stats | jq '{total, pending, by_severity}'

# Check all services
docker compose ps

# View live logs
docker compose logs -f webhook-receiver
docker compose logs -f telegraf
```
