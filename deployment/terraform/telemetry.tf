locals {
  telemetry_dataset_id = replace("${var.service_name}_${var.environment}_telemetry", "-", "_")
}

# GCS bucket for privacy-preserving GenAI telemetry completions & audit exports.
resource "google_storage_bucket" "telemetry_logs" {
  name                        = "${var.project_id}-${var.service_name}-${var.environment}-logs"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = var.environment != "prod"
  depends_on                  = [google_project_service.enabled_apis]

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_iam_member" "app_sa_logs_writer" {
  bucket = google_storage_bucket.telemetry_logs.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.app_sa.email}"
}

# BigQuery dataset capturing structured Intent-vs-Outcome and GenAI telemetry logs.
resource "google_bigquery_dataset" "telemetry" {
  dataset_id                 = local.telemetry_dataset_id
  friendly_name              = "SilverShield Guardian AgentOps Telemetry"
  description                = "Structured JSON audit logs (Intent vs Outcome) and GenAI metrics."
  location                   = var.region
  delete_contents_on_destroy = var.environment != "prod"
  depends_on                 = [google_project_service.enabled_apis]
}

resource "google_logging_project_sink" "agent_audit_to_bq" {
  name                   = "${var.service_name}-${var.environment}-audit-sink"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.telemetry.dataset_id}"
  filter                 = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\" AND jsonPayload.phase:(\"INTENT\" OR \"OUTCOME\")"
  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

resource "google_bigquery_dataset_iam_member" "sink_bq_writer" {
  dataset_id = google_bigquery_dataset.telemetry.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.agent_audit_to_bq.writer_identity
}
