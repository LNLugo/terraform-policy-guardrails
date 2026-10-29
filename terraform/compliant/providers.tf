terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# offline_plan = true lets CI run `terraform plan` with no AWS account.
# Plans that only create resources need no API calls, so the gate can run
# on every pull request without cloud credentials.
provider "aws" {
  region                      = var.region
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan
}
