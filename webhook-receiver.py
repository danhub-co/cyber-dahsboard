#!/usr/bin/env python3
"""
Security Alert Webhook Receiver
Receives alerts from Grafana and processes them with acknowledgment/escalation workflow
"""

from flask import Flask, request, jsonify
import json
import logging
import os
import smtplib
import threading
import time
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.getenv('ALERT_LOG_FILE', 'alerts.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

SEVERITY_LEVELS = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}

INFLUXDB_URL   = os.getenv('INFLUXDB_URL', 'http://influxdb:8086')
INFLUXDB_TOKEN = os.getenv('INFLUXDB_TOKEN', '')
INFLUXDB_ORG   = os.getenv('INFLUXDB_ORG', 'my-org')
ALERT_METRICS_BUCKET = 'alert_metrics'

# Escalation timeouts in seconds per severity (default: critical=5min, high=15min)
ESCALATION_TIMEOUTS = {
    'critical': int(os.getenv('ESCALATION_TIMEOUT_CRITICAL', 300)),
    'high':     int(os.getenv('ESCALATION_TIMEOUT_HIGH', 900)),
}


class AlertProcessor:
    def __init__(self):
        self.alerts_file = Path('alerts_received.json')
        self.alerts_history = []
        self.load_history()
        self._start_escalation_worker()

    def load_history(self):
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r') as f:
                    self.alerts_history = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load alert history: {e}")

    def save_history(self):
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump(self.alerts_history, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving alert history: {e}")

    # ------------------------------------------------------------------ #
    #  InfluxDB metrics writer                                             #
    # ------------------------------------------------------------------ #
    def write_metric(self, measurement, fields, tags=None):
        if not INFLUXDB_TOKEN:
            return
        tag_str = ''
        if tags:
            tag_str = ',' + ','.join(f"{k}={v}" for k, v in tags.items())
        field_str = ','.join(f"{k}={v}i" if isinstance(v, int) else f"{k}={v}" for k, v in fields.items())
        line = f"{measurement}{tag_str} {field_str}"
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{INFLUXDB_URL}/api/v2/write?org={INFLUXDB_ORG}&bucket={ALERT_METRICS_BUCKET}&precision=s",
                data=line.encode(),
                headers={'Authorization': f'Token {INFLUXDB_TOKEN}', 'Content-Type': 'text/plain'},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            logger.warning(f"Failed to write metric to InfluxDB: {e}")

    def write_alert_metrics(self):
        valid = [a for a in self.alerts_history if a.get('id')]
        total        = len(valid)
        pending      = sum(1 for a in valid if not a.get('acknowledged'))
        acknowledged = sum(1 for a in valid if a.get('acknowledged'))
        escalated    = sum(1 for a in valid if a.get('escalation_count', 0) > 0)
        ack_rate     = round((acknowledged / total * 100), 2) if total > 0 else 0.0

        by_severity = {}
        for a in valid:
            s = a.get('severity', 'unknown')
            by_severity[s] = by_severity.get(s, 0) + 1

        self.write_metric('alert_health', {
            'total': total, 'pending': pending,
            'acknowledged': acknowledged, 'escalated': escalated,
            'ack_rate': ack_rate
        })
        for severity, count in by_severity.items():
            self.write_metric('alert_by_severity', {'count': count}, tags={'severity': severity})

    # ------------------------------------------------------------------ #
    #  Email                                                               #
    # ------------------------------------------------------------------ #
    def send_email(self, subject, fields, actions=None):
        smtp_host, smtp_port = os.getenv('SMTP_HOST', 'smtp.gmail.com:587').rsplit(':', 1)
        smtp_user     = os.getenv('SMTP_USER', '')
        smtp_password = os.getenv('SMTP_PASSWORD', '')
        smtp_from     = os.getenv('SMTP_FROM_ADDRESS', smtp_user)
        recipient     = os.getenv('ALERT_EMAIL', smtp_user)

        if not smtp_user or not smtp_password:
            logger.warning('SMTP not configured, skipping email notification')
            return

        try:
            rows = ''.join(
                f'<tr><td style="padding:6px 12px;border:1px solid #ddd;font-weight:bold;'
                f'background:#f5f5f5;white-space:nowrap">{k}</td>'
                f'<td style="padding:6px 12px;border:1px solid #ddd">{v}</td></tr>'
                for k, v in fields.items()
            )
            action_list = ''.join(f'<li style="margin:4px 0">{a}</li>' for a in (actions or []))
            actions_block = f'<h3 style="color:#333">Recommended Actions</h3><ol>{action_list}</ol>' if action_list else ''
            html = f"""
<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333">
  <h2 style="color:#c0392b">{subject}</h2>
  <table style="border-collapse:collapse;width:100%;max-width:620px">
    {rows}
  </table>
  {actions_block}
  <p style="color:#aaa;font-size:11px;margin-top:20px">
    Cyber Dashboard &mdash; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
  </p>
</body></html>"""

            msg = MIMEMultipart('alternative')
            msg['From']    = smtp_from
            msg['To']      = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_from, recipient, msg.as_string())
            logger.info(f'Email sent to {recipient}: {subject}')
        except Exception as e:
            logger.error(f'Failed to send email: {e}')

    # ------------------------------------------------------------------ #
    #  Escalation worker                                                   #
    # ------------------------------------------------------------------ #
    def _start_escalation_worker(self):
        def worker():
            while True:
                time.sleep(60)
                self._check_escalations()
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        logger.info('Escalation worker started')

    def _check_escalations(self):
        now = datetime.now(timezone.utc)
        for alert in self.alerts_history:
            if alert.get('acknowledged'):
                continue
            severity = alert.get('severity', '')
            if severity not in ESCALATION_TIMEOUTS:
                continue

            created = datetime.fromisoformat(alert['timestamp'])
            elapsed = (now - created).total_seconds()
            timeout = ESCALATION_TIMEOUTS[severity]
            escalations = alert.get('escalation_count', 0)

            if elapsed >= timeout * (escalations + 1):
                alert['escalation_count'] = escalations + 1
                self.save_history()
                logger.warning(
                    f"Escalating unacknowledged alert {alert['id']} "
                    f"[{severity}] (escalation #{alert['escalation_count']})"
                )
                self.send_email(
                    subject=f"⚠️ ESCALATION #{alert['escalation_count']}: {alert['name']} [{severity.upper()}] unacknowledged",
                    fields={
                        'Alert ID':   alert['id'],
                        'Name':       alert['name'],
                        'Severity':   severity.upper(),
                        'Fired At':   alert['timestamp'],
                        'Elapsed':    f"{int(elapsed // 60)} minutes",
                        'Escalation': f"#{alert['escalation_count']}",
                        'Action':     f"POST /alerts/{alert['id']}/acknowledge",
                    }
                )

    # ------------------------------------------------------------------ #
    #  Acknowledgment                                                      #
    # ------------------------------------------------------------------ #
    def acknowledge_alert(self, alert_id, note=''):
        for alert in self.alerts_history:
            if alert.get('id') == alert_id:
                if alert.get('acknowledged'):
                    return {'error': 'Alert already acknowledged'}, 400
                alert['acknowledged']    = True
                alert['acknowledged_at'] = datetime.now(timezone.utc).isoformat()
                alert['acknowledge_note'] = note
                self.save_history()
                self.write_alert_metrics()
                logger.info(f"Alert {alert_id} acknowledged. Note: {note}")
                return alert, 200
        return {'error': 'Alert not found'}, 404

    def get_pending_alerts(self):
        return [a for a in self.alerts_history if not a.get('acknowledged')]

    # ------------------------------------------------------------------ #
    #  Alert processing                                                    #
    # ------------------------------------------------------------------ #
    def process_alert(self, alert_data):
        try:
            status       = alert_data.get('status', 'unknown')
            group_labels  = alert_data.get('groupLabels', {})
            common_labels = alert_data.get('commonLabels', {})
            alert_name   = group_labels.get('alertname', 'Unknown')
            severity     = common_labels.get('severity', 'unknown').lower()

            logger.info(f"Processing alert: {alert_name} [Status: {status}, Severity: {severity}]")

            if 'failed_logins' in alert_name.lower():
                self.handle_failed_logins(alert_data)
            elif 'intrusion' in alert_name.lower() or 'banned' in alert_name.lower():
                self.handle_intrusion_detection(alert_data)
            elif 'http' in alert_name.lower() or 'error' in alert_name.lower():
                self.handle_http_errors(alert_data)
            elif 'cpu' in alert_name.lower() or 'load' in alert_name.lower():
                self.handle_system_issues(alert_data)

            alert_record = {
                'id':               str(uuid.uuid4()),
                'timestamp':        datetime.now(timezone.utc).isoformat(),
                'name':             alert_name,
                'severity':         severity,
                'status':           status,
                'acknowledged':     False,
                'acknowledged_at':  None,
                'acknowledge_note': None,
                'escalation_count': 0,
                'data':             alert_data
            }
            self.alerts_history.append(alert_record)
            self.save_history()
            self.write_alert_metrics()
            return alert_record

        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return None

    def handle_failed_logins(self, alert_data):
        logger.critical("🚨 FAILED LOGIN ALERT DETECTED")
        description = alert_data.get('commonAnnotations', {}).get('description', 'Unknown')
        logger.critical(f"Description: {description}")
        actions = [
            "Review /var/log/auth.log on target system",
            "Check source IPs of failed attempts",
            "Consider blocking IPs via fail2ban",
            "Review user account access controls",
            "Consider enabling MFA"
        ]
        for action in actions:
            logger.critical(action)
        self.send_email(
            subject='🚨 CRITICAL: Failed Login Alert Detected',
            fields={
                'Alert':     'High Failed Login Attempts',
                'Severity':  'HIGH',
                'Description': description,
                'Time':      datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                'Threshold': '&gt;10 failed logins in 10 minutes',
                'Runbook':   'RB-01 — See RUNBOOKS.md',
            },
            actions=actions
        )

    def handle_intrusion_detection(self, alert_data):
        logger.critical("🚨 INTRUSION DETECTED - IP BANNED")
        description = alert_data.get('commonAnnotations', {}).get('description', 'Unknown')
        logger.critical(f"Description: {description}")
        actions = [
            "IMMEDIATE: Verify the banned IP is malicious",
            "Check detailed fail2ban logs: /var/log/fail2ban.log",
            "Investigate attack patterns",
            "Review affected services (SSH, HTTP, etc.)",
            "Consider notification to upstream providers",
            "Add IP to permanent blocklist if pattern confirmed"
        ]
        for action in actions:
            logger.critical(action)
        self.send_email(
            subject='🚨 CRITICAL: Intrusion Detected - IP Banned',
            fields={
                'Alert':     'IP Addresses Banned by Fail2Ban',
                'Severity':  'CRITICAL',
                'Description': description,
                'Time':      datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                'Threshold': '&gt;0 ban actions in 5 minutes',
                'Runbook':   'RB-02 — See RUNBOOKS.md',
            },
            actions=actions
        )

    def handle_http_errors(self, alert_data):
        logger.warning("⚠️ HIGH HTTP ERROR RATE DETECTED")
        description = alert_data.get('commonAnnotations', {}).get('description', 'Unknown')
        logger.warning(f"Description: {description}")
        for action in [
            "1. Check web server error logs (nginx/apache)",
            "2. Verify backend application status",
            "3. Check database connectivity",
            "4. Review resource utilization (disk, memory)",
            "5. Consider DDoS mitigation if sudden spike"
        ]:
            logger.warning(action)

    def handle_system_issues(self, alert_data):
        logger.warning("⚠️ SYSTEM RESOURCE ALERT")
        description = alert_data.get('commonAnnotations', {}).get('description', 'Unknown')
        logger.warning(f"Description: {description}")
        for action in [
            "1. Identify top processes using resources: ps aux | sort -k3,3 -nr",
            "2. Check for memory leaks or zombie processes",
            "3. Review running services for unnecessary load",
            "4. Consider auto-scaling if in cloud environment",
            "5. Plan capacity upgrade if baseline trending high"
        ]:
            logger.warning(action)

    def get_statistics(self):
        total_alerts = len(self.alerts_history)
        by_severity, by_name = {}, {}
        for alert in self.alerts_history:
            s = alert.get('severity', 'unknown')
            n = alert.get('name', 'unknown')
            by_severity[s] = by_severity.get(s, 0) + 1
            by_name[n]     = by_name.get(n, 0) + 1
        return {
            'total':       total_alerts,
            'pending':     len(self.get_pending_alerts()),
            'by_severity': by_severity,
            'by_name':     by_name,
            'recent':      self.alerts_history[-10:] if self.alerts_history else []
        }


# ------------------------------------------------------------------ #
#  App & routes                                                        #
# ------------------------------------------------------------------ #
processor = AlertProcessor()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()}), 200


@app.route('/alerts', methods=['POST'])
def receive_alert():
    try:
        alert_data = request.get_json()
        if not alert_data:
            return jsonify({'error': 'Empty payload'}), 400

        logger.info(f"Received alert payload: {json.dumps(alert_data, indent=2)}")
        result = processor.process_alert(alert_data)

        if result:
            return jsonify({
                'status':     'processed',
                'id':         result.get('id'),
                'alert_name': result.get('name'),
                'severity':   result.get('severity'),
                'timestamp':  result.get('timestamp')
            }), 200
        return jsonify({'status': 'error', 'message': 'Failed to process alert'}), 500

    except Exception as e:
        logger.error(f"Error in receive_alert: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    note = request.get_json(silent=True) or {}
    result, status = processor.acknowledge_alert(alert_id, note.get('note', ''))
    return jsonify(result), status


@app.route('/alerts/pending', methods=['GET'])
def get_pending():
    return jsonify(processor.get_pending_alerts()), 200


@app.route('/alerts/history', methods=['GET'])
def get_alerts_history():
    limit = request.args.get('limit', 100, type=int)
    return jsonify(processor.alerts_history[-limit:]), 200


@app.route('/alerts/severity/<severity>', methods=['GET'])
def get_alerts_by_severity(severity):
    filtered = [a for a in processor.alerts_history if a.get('severity') == severity.lower()]
    return jsonify(filtered), 200


@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify(processor.get_statistics()), 200


if __name__ == '__main__':
    host  = os.getenv('FLASK_HOST', '127.0.0.1')
    port  = int(os.getenv('FLASK_PORT', '5000'))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info("🚀 Starting Security Alert Webhook Receiver")
    logger.info(f"Listening on http://{host}:{port}/alerts")
    app.run(host=host, port=port, debug=debug)
