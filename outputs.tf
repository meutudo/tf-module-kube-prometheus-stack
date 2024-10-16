output "grafana_url" {
  value = "http://grafana.${var.cluster_domain}"
}

output "prometheus_status" {
  value = helm_release.kube_prometheus_stack.status
}
