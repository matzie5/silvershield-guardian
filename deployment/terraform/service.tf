# Artifact Registry repository for SilverShield container images.
resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = var.service_name
  format        = "DOCKER"
  description   = "Container images for SilverShield Guardian ADK service."
  depends_on    = [google_project_service.enabled_apis]
}

# Cloud Run v2 Service hosting the SilverShield ADK FastAPI server.
resource "google_cloud_run_v2_service" "silvershield" {
  name       = var.service_name
  location   = var.region
  ingress    = "INGRESS_TRAFFIC_ALL"
  depends_on = [
    google_project_service.enabled_apis,
    google_project_iam_member.app_sa_roles,
    google_secret_manager_secret_iam_member.app_sa_session_db_accessor,
  ]

  template {
    service_account = google_service_account.app_sa.email

    scaling {
      min_instance_count = var.environment == "prod" ? 1 : 0
      max_instance_count = 10
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.sessions.connection_name]
      }
    }

    containers {
      image = var.container_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      # Non-sensitive runtime configuration
      env {
        name  = "APP_ENV"
        value = var.environment
      }
      env {
        name  = "LOG_FORMAT"
        value = "json"
      }
      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "USE_SECRET_MANAGER"
        value = "true"
      }
      env {
        name  = "SILVERSHIELD_FAST_MODEL"
        value = var.fast_model_name
      }
      env {
        name  = "SILVERSHIELD_REASONING_MODEL"
        value = var.reasoning_model_name
      }
      env {
        name  = "SESSION_BACKEND"
        value = "postgres"
      }
      env {
        name  = "SESSION_DB_SECRET_NAME"
        value = google_secret_manager_secret.session_db_url.secret_id
      }
      env {
        name  = "ENABLE_CLOUD_DLP"
        value = tostring(var.enable_cloud_dlp)
      }
      env {
        name  = "ENABLE_MODEL_ARMOR"
        value = tostring(var.enable_model_armor)
      }
      env {
        name  = "MODEL_ARMOR_TEMPLATE_ID"
        value = var.model_armor_template_id
      }
      env {
        name  = "OTEL_SDK_DISABLED"
        value = "false"
      }
      env {
        name  = "OTEL_SERVICE_NAME"
        value = var.service_name
      }
      env {
        name  = "OTEL_TRACES_EXPORTER"
        value = "google_cloud_trace"
      }
      env {
        name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
        value = "NO_CONTENT"
      }
      env {
        name  = "LOGS_BUCKET_NAME"
        value = google_storage_bucket.telemetry_logs.name
      }
      env {
        name  = "BQ_ANALYTICS_DATASET_ID"
        value = google_bigquery_dataset.telemetry.dataset_id
      }
      env {
        name  = "VERTEX_AI_SEARCH_DATASTORE_ID"
        value = var.enable_vertex_ai_search ? google_discovery_engine_data_store.scam_factcheck_store[0].name : ""
      }

      # Secure secret injection directly from GCP Secret Manager (zero plaintext secrets)
      env {
        name = "SESSION_DB_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_db_url.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 6
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds = 30
      }
    }
  }
}
