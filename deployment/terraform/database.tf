# Persistent Cloud SQL PostgreSQL instance backing ADK `DatabaseSessionService`.
resource "google_sql_database_instance" "sessions" {
  name                = "${var.service_name}-sessions-${var.environment}"
  database_version    = "POSTGRES_16"
  region              = var.region
  deletion_protection = var.environment == "prod"
  depends_on          = [google_project_service.enabled_apis]

  settings {
    tier              = var.db_tier
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = var.environment == "prod"
      start_time                     = "03:00"
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }
}

resource "google_sql_database" "silvershield_sessions" {
  name     = "silvershield_sessions"
  instance = google_sql_database_instance.sessions.name
}
