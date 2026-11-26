output "cloud_run_service_url" {
  description = "HTTPS endpoint of the deployed SilverShield Guardian Cloud Run service."
  value       = google_cloud_run_v2_service.silvershield.uri
}

output "runtime_service_account_email" {
  description = "Least-privilege service account email used by SilverShield Guardian."
  value       = google_service_account.app_sa.email
}

output "cicd_service_account_email" {
  description = "Service account email used by GitHub Actions CI/CD via WIF."
  value       = google_service_account.cicd_runner_sa.email
}

output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository path."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL connection name backing persistent ADK DatabaseSessionService."
  value       = google_sql_database_instance.sessions.connection_name
}

output "session_db_secret_id" {
  description = "GCP Secret Manager secret ID holding the session DB connection URI."
  value       = google_secret_manager_secret.session_db_url.secret_id
}

output "telemetry_bigquery_dataset" {
  description = "BigQuery dataset ID storing structured Intent-vs-Outcome audit logs."
  value       = google_bigquery_dataset.telemetry.dataset_id
}
