resource "null_resource" "test_grafana" {
  provisioner "local-exec" {
    command = "curl -s -o /dev/null -w '%{http_code}' ${module.kube-prometheus-stack.grafana_url}"
  }

  depends_on = [helm_release.kube_prometheus_stack]
}
