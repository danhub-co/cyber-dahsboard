#!/bin/bash

# Cyber Dashboard Setup Script
# This script helps you set up secure credentials for production use

set -e

echo "🔐 Cyber Dashboard - Production Setup"
echo "======================================"
echo ""

# Check if .env already exists
if [ -f .env ]; then
    read -p "⚠️  .env file already exists. Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

# Generate secure random passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

generate_token() {
    openssl rand -hex 32
}

echo "Generating secure credentials..."
echo ""

INFLUXDB_PASSWORD=$(generate_password)
INFLUXDB_TOKEN=$(generate_token)
GRAFANA_PASSWORD=$(generate_password)

# Create .env file
cat > .env << EOF
# InfluxDB Configuration
INFLUXDB_USERNAME=admin
INFLUXDB_PASSWORD=${INFLUXDB_PASSWORD}
INFLUXDB_ORG=my-org
INFLUXDB_BUCKET=security_logs
INFLUXDB_TOKEN=${INFLUXDB_TOKEN}
INFLUXDB_PORT=8087

# Grafana Configuration
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
GRAFANA_PORT=3000

# Webhook Configuration (Optional)
WEBHOOK_PORT=5000
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
EOF

chmod 600 .env

echo "✅ Credentials generated successfully!"
echo ""
echo "📝 Your credentials (save these securely):"
echo "==========================================="
echo ""
echo "InfluxDB:"
echo "  Username: admin"
echo "  Password: ${INFLUXDB_PASSWORD}"
echo "  Token:    ${INFLUXDB_TOKEN}"
echo ""
echo "Grafana:"
echo "  Username: admin"
echo "  Password: ${GRAFANA_PASSWORD}"
echo "  URL:      http://localhost:3000"
echo ""
echo "⚠️  IMPORTANT: Save these credentials in a secure location!"
echo "   The .env file has been created with restricted permissions."
echo ""
echo "🚀 Next steps:"
echo "   1. Review and customize .env if needed"
echo "   2. Run: docker-compose up -d"
echo "   3. Access Grafana at http://localhost:3000"
echo ""
