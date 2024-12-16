target "cloak" {
  context = "./"
  dockerfile = "Dockerfile"
  tags = ["cloak:latest"]
}

group "default" {
  targets = ["cloak"]
}
