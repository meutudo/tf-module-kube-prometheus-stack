grafana:
  enabled: true
  adminPassword: "${GRAFANA_ADMIN_PASSWORD}"

prometheus:
  enabled: true
  serviceMonitor:
    enabled: true
