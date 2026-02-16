#!/usr/bin/env python3
"""
Security Alert Webhook Receiver
Receives alerts from Grafana and processes them for various integrations
"""

from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alerts.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Alert severity levels
SEVERITY_LEVELS = {
    'critical': 1,
    'high': 2,
    'medium': 3,
    'low': 4,
    'info': 5
}

class AlertProcessor:
    def __init__(self):
        self.alerts_file = Path('alerts_received.json')
        self.alerts_history = []
        self.load_history()
    
    def load_history(self):
        """Load alert history from file"""
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r') as f:
                    self.alerts_history = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load alert history: {e}")
    
    def save_history(self):
        """Save alert history to file"""
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump(self.alerts_history, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving alert history: {e}")
    
    def process_alert(self, alert_data):
        """Process incoming alert"""
        try:
            # Extract alert information
            status = alert_data.get('status', 'unknown')
            group_labels = alert_data.get('groupLabels', {})
            common_labels = alert_data.get('commonLabels', {})
            
            alert_name = group_labels.get('alertname', 'Unknown')
            severity = common_labels.get('severity', 'unknown').lower()
            
            logger.info(f"Processing alert: {alert_name} [Status: {status}, Severity: {severity}]")
            
            # Handle different alert types
            if 'failed_logins' in alert_name.lower():
                self.handle_failed_logins(alert_data)
            elif 'intrusion' in alert_name.lower() or 'banned' in alert_name.lower():
                self.handle_intrusion_detection(alert_data)
            elif 'http' in alert_name.lower() or 'error' in alert_name.lower():
                self.handle_http_errors(alert_data)
            elif 'cpu' in alert_name.lower() or 'load' in alert_name.lower():
                self.handle_system_issues(alert_data)
            
            # Store alert in history
            alert_record = {
                'timestamp': datetime.now().isoformat(),
                'name': alert_name,
                'severity': severity,
                'status': status,
                'data': alert_data
            }
            self.alerts_history.append(alert_record)
            self.save_history()
            
            return alert_record
        
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return None
    
    def handle_failed_logins(self, alert_data):
        """Handle failed login alerts"""
        logger.critical("🚨 FAILED LOGIN ALERT DETECTED")
        
        annotations = alert_data.get('commonAnnotations', {})
        description = annotations.get('description', 'Unknown')
        
        logger.critical(f"Description: {description}")
        
        # Actions to take on failed login alert
        actions = [
            "1. Review /var/log/auth.log on target system",
            "2. Check source IPs of failed attempts",
            "3. Consider blocking IPs via fail2ban",
            "4. Review user account access controls",
            "5. Consider enabling MFA"
        ]
        
        for action in actions:
            logger.critical(action)
    
    def handle_intrusion_detection(self, alert_data):
        """Handle intrusion detection alerts"""
        logger.critical("🚨 INTRUSION DETECTED - IP BANNED")
        
        annotations = alert_data.get('commonAnnotations', {})
        description = annotations.get('description', 'Unknown')
        
        logger.critical(f"Description: {description}")
        
        # Actions to take on intrusion alert
        actions = [
            "1. IMMEDIATE: Verify the banned IP is malicious",
            "2. Check detailed fail2ban logs: /var/log/fail2ban.log",
            "3. Investigate attack patterns",
            "4. Review affected services (SSH, HTTP, etc.)",
            "5. Consider notification to upstream providers",
            "6. Add IP to permanent blocklist if pattern confirmed"
        ]
        
        for action in actions:
            logger.critical(action)
    
    def handle_http_errors(self, alert_data):
        """Handle HTTP error alerts"""
        logger.warning("⚠️ HIGH HTTP ERROR RATE DETECTED")
        
        annotations = alert_data.get('commonAnnotations', {})
        description = annotations.get('description', 'Unknown')
        
        logger.warning(f"Description: {description}")
        
        # Actions to take on HTTP error alert
        actions = [
            "1. Check web server error logs (nginx/apache)",
            "2. Verify backend application status",
            "3. Check database connectivity",
            "4. Review resource utilization (disk, memory)",
            "5. Consider DDoS mitigation if sudden spike"
        ]
        
        for action in actions:
            logger.warning(action)
    
    def handle_system_issues(self, alert_data):
        """Handle system resource alerts"""
        logger.warning("⚠️ SYSTEM RESOURCE ALERT")
        
        annotations = alert_data.get('commonAnnotations', {})
        description = annotations.get('description', 'Unknown')
        
        logger.warning(f"Description: {description}")
        
        # Actions to take on system alert
        actions = [
            "1. Identify top processes using resources: ps aux | sort -k3,3 -nr",
            "2. Check for memory leaks or zombie processes",
            "3. Review running services for unnecessary load",
            "4. Consider auto-scaling if in cloud environment",
            "5. Plan capacity upgrade if baseline trending high"
        ]
        
        for action in actions:
            logger.warning(action)
    
    def get_statistics(self):
        """Get alert statistics"""
        total_alerts = len(self.alerts_history)
        by_severity = {}
        by_name = {}
        
        for alert in self.alerts_history:
            severity = alert.get('severity', 'unknown')
            name = alert.get('name', 'unknown')
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_name[name] = by_name.get(name, 0) + 1
        
        return {
            'total': total_alerts,
            'by_severity': by_severity,
            'by_name': by_name,
            'recent': self.alerts_history[-10:] if self.alerts_history else []
        }

# Initialize alert processor
processor = AlertProcessor()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200

@app.route('/alerts', methods=['POST'])
def receive_alert():
    """Receive and process alerts from Grafana"""
    try:
        alert_data = request.get_json()
        
        if not alert_data:
            logger.warning("Received empty alert payload")
            return jsonify({'error': 'Empty payload'}), 400
        
        logger.info(f"Received alert payload: {json.dumps(alert_data, indent=2)}")
        
        # Process the alert
        result = processor.process_alert(alert_data)
        
        if result:
            return jsonify({
                'status': 'processed',
                'alert_name': result.get('name'),
                'severity': result.get('severity'),
                'timestamp': result.get('timestamp')
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to process alert'}), 500
    
    except Exception as e:
        logger.error(f"Error in receive_alert: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get alert statistics"""
    return jsonify(processor.get_statistics()), 200

@app.route('/alerts-history', methods=['GET'])
def get_alerts_history():
    """Get alert history"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(processor.alerts_history[-limit:]), 200

@app.route('/alerts/<severity>', methods=['GET'])
def get_alerts_by_severity(severity):
    """Get alerts filtered by severity"""
    filtered = [a for a in processor.alerts_history if a.get('severity') == severity.lower()]
    return jsonify(filtered), 200

if __name__ == '__main__':
    logger.info("🚀 Starting Security Alert Webhook Receiver")
    logger.info("Listening on http://0.0.0.0:5000/alerts")
    app.run(host='0.0.0.0', port=5000, debug=False)
