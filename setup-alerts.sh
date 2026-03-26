#!/bin/bash

# Grafana Alerts Setup Script
# This script configures alert rules and notification channels for security monitoring

set -e

GRAFANA_URL="http://localhost:3000"
ADMIN_USER="admin"
ADMIN_PASSWORD=$(grep GRAFANA_ADMIN_PASSWORD .env | cut -d= -f2)

echo "🚨 Setting up Grafana Alerts for Security Events..."

# 1. Create Webhook Notification Channel
echo "Creating Webhook Notification Channel..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/contact-points \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "webhook-channel",
    "name": "Security Webhook",
    "type": "webhook",
    "settings": {
      "url": "http://webhook-receiver:5000/alerts",
      "httpMethod": "POST"
    },
    "noDataState": "NoData",
    "execErrState": "Alerting"
  }' | jq . 2>/dev/null && echo "✅ Webhook channel created" || echo "⚠️ Webhook channel setup (may already exist)"

# 2. Create Email Notification Channel (template)
echo "Creating Email Notification Channel Template..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/contact-points \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "email-channel",
    "name": "Security Email Alerts",
    "type": "email",
    "settings": {
      "addresses": "daniotest4@gmail.com"
    },
    "noDataState": "NoData",
    "execErrState": "Alerting"
  }' | jq . 2>/dev/null && echo "✅ Email channel created" || echo "⚠️ Email channel setup (may already exist)"

# 3. Create Alert Rule for Failed Logins
echo "Creating Failed Login Attempts Alert..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/alert-rules \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "failed-logins-alert",
    "title": "High Failed Login Attempts",
    "condition": "B",
    "data": [
      {
        "refId": "A",
        "queryType": "flux",
        "relativeTimeRange": {
          "from": 600,
          "to": 0
        },
        "datasourceUid": "P951FEA4DE68E13C5",
        "model": {
          "expr": "from(bucket: \"security_logs\") |> range(start: -10m) |> filter(fn: (r) => r._measurement == \"failed_logins\") |> count()",
          "hide": false,
          "intervalFactor": 1,
          "refId": "A"
        }
      },
      {
        "refId": "B",
        "queryType": "",
        "datasourceUid": "-100",
        "conditions": [
          {
            "evaluator": {
              "params": [10],
              "type": "gt"
            },
            "operator": {
              "type": "and"
            },
            "query": {
              "params": ["A"]
            },
            "type": "query"
          }
        ],
        "reducer": {
          "params": [],
          "type": "last"
        },
        "type": "threshold"
      }
    ],
    "folderUID": "security-alerts",
    "intervalSeconds": 60,
    "noDataState": "NoData",
    "execErrState": "Alerting",
    "for": "5m",
    "annotations": {
      "description": "More than 10 failed login attempts detected in the last 10 minutes",
      "runbook_url": "https://example.com/runbooks/failed-logins",
      "summary": "Failed Login Attack"
    },
    "labels": {
      "severity": "high",
      "team": "security"
    },
    "notification_channels": ["webhook-channel", "email-channel"],
    "alert_rule_tags": {
      "severity": "high"
    }
  }' | jq . 2>/dev/null && echo "✅ Failed login alert created" || echo "⚠️ Failed login alert setup"

# 4. Create Alert Rule for Intrusion Detection
echo "Creating Intrusion Detection Alert..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/alert-rules \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "intrusion-detection-alert",
    "title": "IP Addresses Banned by Fail2Ban",
    "condition": "B",
    "data": [
      {
        "refId": "A",
        "queryType": "flux",
        "relativeTimeRange": {
          "from": 300,
          "to": 0
        },
        "datasourceUid": "P951FEA4DE68E13C5",
        "model": {
          "expr": "from(bucket: \"intrusion_detection\") |> range(start: -5m) |> filter(fn: (r) => r._measurement == \"fail2ban_actions\" and r.action == \"Ban\") |> count()",
          "hide": false,
          "intervalFactor": 1,
          "refId": "A"
        }
      },
      {
        "refId": "B",
        "queryType": "",
        "datasourceUid": "-100",
        "conditions": [
          {
            "evaluator": {
              "params": [1],
              "type": "gt"
            },
            "operator": {
              "type": "and"
            },
            "query": {
              "params": ["A"]
            },
            "type": "query"
          }
        ],
        "reducer": {
          "params": [],
          "type": "last"
        },
        "type": "threshold"
      }
    ],
    "folderUID": "security-alerts",
    "intervalSeconds": 60,
    "noDataState": "NoData",
    "execErrState": "Alerting",
    "for": "1m",
    "annotations": {
      "description": "IP addresses have been banned for suspicious activity",
      "runbook_url": "https://example.com/runbooks/intrusion-detection",
      "summary": "Intrusion Detected - IPs Banned"
    },
    "labels": {
      "severity": "critical",
      "team": "security"
    },
    "notification_channels": ["webhook-channel", "email-channel"],
    "alert_rule_tags": {
      "severity": "critical"
    }
  }' | jq . 2>/dev/null && echo "✅ Intrusion detection alert created" || echo "⚠️ Intrusion detection alert setup"

# 5. Create Alert Rule for HTTP Errors
echo "Creating HTTP Error Rate Alert..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/alert-rules \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "http-error-alert",
    "title": "High HTTP Error Rate",
    "condition": "B",
    "data": [
      {
        "refId": "A",
        "queryType": "flux",
        "relativeTimeRange": {
          "from": 300,
          "to": 0
        },
        "datasourceUid": "P951FEA4DE68E13C5",
        "model": {
          "expr": "from(bucket: \"network_logs\") |> range(start: -5m) |> filter(fn: (r) => r._measurement =~ /nginx_access|apache_access/ and r.http_code >= \"500\") |> count()",
          "hide": false,
          "intervalFactor": 1,
          "refId": "A"
        }
      },
      {
        "refId": "B",
        "queryType": "",
        "datasourceUid": "-100",
        "conditions": [
          {
            "evaluator": {
              "params": [50],
              "type": "gt"
            },
            "operator": {
              "type": "and"
            },
            "query": {
              "params": ["A"]
            },
            "type": "query"
          }
        ],
        "reducer": {
          "params": [],
          "type": "last"
        },
        "type": "threshold"
      }
    ],
    "folderUID": "security-alerts",
    "intervalSeconds": 60,
    "noDataState": "NoData",
    "execErrState": "Alerting",
    "for": "5m",
    "annotations": {
      "description": "Detected 50+ HTTP 5xx errors in the last 5 minutes",
      "runbook_url": "https://example.com/runbooks/http-errors",
      "summary": "Server Error Rate High"
    },
    "labels": {
      "severity": "high",
      "team": "devops"
    },
    "notification_channels": ["webhook-channel", "email-channel"],
    "alert_rule_tags": {
      "severity": "high"
    }
  }' | jq . 2>/dev/null && echo "✅ HTTP error alert created" || echo "⚠️ HTTP error alert setup"

# 6. Create Alert Rule for High System Load
echo "Creating High System Load Alert..."
curl -s -u $ADMIN_USER:$ADMIN_PASSWORD -X POST \
  $GRAFANA_URL/api/v1/provisioning/alert-rules \
  -H "Content-Type: application/json" \
  -d '{
    "uid": "system-load-alert",
    "title": "High CPU Usage Detected",
    "condition": "B",
    "data": [
      {
        "refId": "A",
        "queryType": "flux",
        "relativeTimeRange": {
          "from": 300,
          "to": 0
        },
        "datasourceUid": "P951FEA4DE68E13C5",
        "model": {
          "expr": "from(bucket: \"system_metrics\") |> range(start: -5m) |> filter(fn: (r) => r._measurement == \"cpu\" and r._field == \"usage_system\") |> aggregateWindow(every: 1m, fn: mean)",
          "hide": false,
          "intervalFactor": 1,
          "refId": "A"
        }
      },
      {
        "refId": "B",
        "queryType": "",
        "datasourceUid": "-100",
        "conditions": [
          {
            "evaluator": {
              "params": [80],
              "type": "gt"
            },
            "operator": {
              "type": "and"
            },
            "query": {
              "params": ["A"]
            },
            "type": "query"
          }
        ],
        "reducer": {
          "params": [],
          "type": "last"
        },
        "type": "threshold"
      }
    ],
    "folderUID": "security-alerts",
    "intervalSeconds": 60,
    "noDataState": "NoData",
    "execErrState": "Alerting",
    "for": "5m",
    "annotations": {
      "description": "CPU usage has exceeded 80% for more than 5 minutes",
      "runbook_url": "https://example.com/runbooks/high-cpu",
      "summary": "High CPU Utilization"
    },
    "labels": {
      "severity": "medium",
      "team": "infrastructure"
    },
    "notification_channels": ["webhook-channel"],
    "alert_rule_tags": {
      "severity": "medium"
    }
  }' | jq . 2>/dev/null && echo "✅ System load alert created" || echo "⚠️ System load alert setup"

echo ""
echo "✅ Alert setup complete!"
echo ""
echo "📋 Configured Alerts:"
echo "  1. Failed Login Attempts (>10 in 10 min) - CRITICAL"
echo "  2. Intrusion Detection (IP Bans) - CRITICAL"
echo "  3. HTTP 5xx Errors (>50 in 5 min) - HIGH"
echo "  4. High CPU Usage (>80% for 5 min) - MEDIUM"
echo ""
echo "📧 Next Steps:"
echo "  1. Update email addresses in notification channels"
echo "  2. Configure webhook URL for custom alerts"
echo "  3. Test alerts by triggering conditions"
echo "  4. Review alert rules in Grafana: Settings > Alert Rules"
