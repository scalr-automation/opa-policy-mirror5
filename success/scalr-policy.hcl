version = "v1"

policy "success_policy" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "advisory_policy" {
  enabled           = true
  enforcement_level = "advisory"
}
