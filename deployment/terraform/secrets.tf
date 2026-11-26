# Secret Manager containers only — secret version payloads are populated out-of-band
# via `gcloud secrets versions add` so no credentials ever exist in Terraform state or Git.

resource "google_secret_manager_secret" "session_db_url" {
  secret_id  = "${var.service_name}-session-db-url"
  depends_on = [google_project_service.enabled_apis]

  replication {
    auto {}
  }

  labels = {
    app         = var.service_name
    environment = var.environment
  }
}

resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id  = "${var.service_name}-gemini-api-key"
  depends_on = [google_project_service.enabled_apis]

  replication {
    auto {}
  }

  labels = {
    app         = var.service_name
    environment = var.environment
  }
}

resource "google_secret_manager_secret_iam_member" "app_sa_session_db_accessor" {
  secret_id = google_secret_manager_secret.session_db_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "app_sa_gemini_key_accessor" {
  secret_id = google_secret_manager_secret.gemini_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app_sa.email}"
}
