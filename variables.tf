variable "namespace" {
  description = "Namespace where the kube-prometheus-stack will be installed."
  type        = string
  default     = "monitoring"
}

variable "grafana_admin_password" {
  description = "Admin password for Grafana."
  type        = string
  sensitive   = true
}

variable "resources" {
  description = "Resource allocation for components."
  type        = map(object({
    requests = map(string)
    limits   = map(string)
  }))
  default = {
    grafana = {
      requests = { cpu = "250m", memory = "512Mi" }
      limits   = { cpu = "1", memory = "1Gi" }
    }
    prometheus = {
      requests = { cpu = "500m", memory = "1Gi" }
      limits   = { cpu = "2", memory = "2Gi" }
    }
  }
}
