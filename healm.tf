resource "helm_release" "kube_prometheus_stack" {
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = var.namespace

  set {
    name  = "grafana.adminPassword"
    value = var.grafana_admin_password
  }

  values = [file("values.yaml")]
}
