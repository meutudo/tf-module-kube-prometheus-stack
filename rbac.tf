resource "kubernetes_role" "prometheus" {
  metadata {
    name      = "prometheus"
    namespace = var.namespace
  }
  ...
}
