variable "project_id" {
  description = "Google Cloud project ID hosting SilverShield Guardian."
  type        = string
}

variable "region" {
  description = "Google Cloud region for Cloud Run, Cloud SQL, and Artifact Registry."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "service_name" {
  description = "Base name for Cloud Run service and related GCP resources."
  type        = string
  default     = "silvershield-guardian"
}

variable "container_image" {
  description = "Artifact Registry container image URI to deploy to Cloud Run."
  type        = string
}

variable "fast_model_name" {
  description = "Fast-tier Gemini model name for triage, tool calls, compaction, and self-eval."
  type        = string
  default     = "gemini-2.5-flash"
}

variable "reasoning_model_name" {
  description = "Reasoning-tier Gemini model name for nuanced risk synthesis and refinement."
  type        = string
  default     = "gemini-2.5-pro"
}

variable "db_tier" {
  description = "Cloud SQL PostgreSQL machine tier for persistent ADK session state."
  type        = string
  default     = "db-f1-micro"
}

variable "enable_cloud_dlp" {
  description = "Enable Google Cloud DLP API in the PII redaction pipeline."
  type        = bool
  default     = true
}

variable "enable_model_armor" {
  description = "Enable Google Cloud Model Armor prompt/response sanitization."
  type        = bool
  default     = false
}

variable "model_armor_template_id" {
  description = "Full resource name of the Cloud Model Armor template (optional)."
  type        = string
  default     = ""
}

variable "enable_vertex_ai_search" {
  description = "Provision a Vertex AI Discovery Engine datastore for scam/fact-check grounding."
  type        = bool
  default     = false
}

variable "github_repository" {
  description = "GitHub repository in 'owner/repo' format for Workload Identity Federation CI/CD."
  type        = string
  default     = ""
}
