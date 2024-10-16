resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
  }
}

module "kube-prometheus-stack" {
  source     = "./helm"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name
  ...
}
