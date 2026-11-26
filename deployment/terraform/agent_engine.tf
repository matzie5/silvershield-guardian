# Optional Vertex AI Search (Discovery Engine) datastore for enterprise-scale
# elder-scam bulletins and verified fact-check knowledge retrieval.
resource "google_discovery_engine_data_store" "scam_factcheck_store" {
  count                       = var.enable_vertex_ai_search ? 1 : 0
  location                    = "global"
  data_store_id               = "${var.service_name}-${var.environment}-scam-kb"
  display_name                = "SilverShield Elder Scam & Fact-Check Knowledge Base"
  industry_vertical           = "GENERIC"
  content_config              = "CONTENT_REQUIRED"
  solution_types              = ["SOLUTION_TYPE_SEARCH"]
  create_advanced_site_search = false
  depends_on                  = [google_project_service.enabled_apis]
}
