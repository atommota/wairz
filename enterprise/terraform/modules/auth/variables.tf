variable "name" {
  type        = string
  description = "Name prefix."
}

variable "domain_suffix" {
  type        = string
  default     = "auth"
  description = "Suffix for the Cognito hosted-UI domain (<name>-<suffix>.auth.<region>.amazoncognito.com). Must be globally unique."
}

variable "invite_only" {
  type        = bool
  default     = true
  description = "Admin-create-user only (no self sign-up) — appropriate for an internal team instance."
}

variable "callback_urls" {
  type        = list(string)
  default     = []
  description = "OAuth callback URLs (e.g. https://<cloudfront-domain>/oauth2/idpresponse)."
}

variable "logout_urls" {
  type        = list(string)
  default     = []
  description = "OAuth logout URLs."
}
