# Dedicated least-privilege runtime service account for SilverShield Guardian.
resource "google_service_account" "app_sa" {
  account_id   = "${var.service_name}-sa"
  display_name = "SilverShield Guardian Runtime Service Account (${var.environment})"
  depends_on   = [google_project_service.enabled_apis]
}

locals {
  app_sa_roles = toset([
    "roles/aiplatform.user",
    "roles/cloudsql.client",
    "roles/cloudtrace.agent",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
    "roles/logging.logWriter",
    "roles/modelarmor.user",
    "roles/monitoring.metricWriter",
  ])
}

resource "google_project_iam_member" "app_sa_roles" {
  for_each = local.app_sa_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.app_sa.email}"
}

# CI/CD service account + GitHub Actions Workload Identity Federation (keyless auth).
resource "google_service_account" "cicd_runner_sa" {
  account_id   = "${var.service_name}-cicd"
  display_name = "SilverShield Guardian CI/CD Runner SA"
  depends_on   = [google_project_service.enabled_apis]
}

locals {
  cicd_roles = toset([
    "roles/artifactregistry.writer",
    "roles/run.developer",
    "roles/iam.serviceAccountUser",
  ])
}

resource "google_project_iam_member" "cicd_sa_roles" {
  for_each = local.cicd_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.cicd_runner_sa.email}"
}

resource "google_iam_workload_identity_pool" "github_pool" {
  count                     = var.github_repository != "" ? 1 : 0
  workload_identity_pool_id = "${var.service_name}-gh-pool"
  display_name              = "GitHub Actions Pool for SilverShield"
  depends_on                = [google_project_service.enabled_apis]
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  count                              = var.github_repository != "" ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = "assertion.repository == '${var.github_repository}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_wif_binding" {
  count              = var.github_repository != "" ? 1 : 0
  service_account_id = google_service_account.cicd_runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool[0].name}/attribute.repository/${var.github_repository}"
}
