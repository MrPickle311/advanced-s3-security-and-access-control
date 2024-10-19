variable "account_id" {
  type = string
  description = "Root account id"
  sensitive = true
  nullable = false
}

variable "region" {
  type = string
  description = "Desired region"
  sensitive = false
  nullable = true
  default = "eu-central-1"
}

data "aws_region" "current" {}