variable "region" {
  type    = string
  default = "us-east-1"
}

variable "offline_plan" {
  type    = bool
  default = false
}

variable "corporate_cidr" {
  description = "Internal range allowed to reach the bastion over SSH"
  type        = string
  default     = "10.20.0.0/16"
}
