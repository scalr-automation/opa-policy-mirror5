version = "v1"

policy "metadata_leak" {
  enabled           = true
  enforcement_level = "advisory"
}

policy "metadata_probe" {
  enabled           = true
  enforcement_level = "advisory"
}
