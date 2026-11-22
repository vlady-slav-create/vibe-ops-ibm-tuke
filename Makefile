.DEFAULT_GOAL := help

TFVARS ?=
TF_ARGS = $(if $(TFVARS),-var-file="$(TFVARS)")
ifneq ($(strip $(AWS_PROFILE)),)
export AWS_PROFILE
endif

.PHONY: help compose compose-down zap-reports package terraform-init terraform-plan terraform-apply terraform-output terraform-destroy

help:
	@printf '%s\n' \
	  'make compose                       Clean start: compose-down, assume publisher role, rebuild, start pipeline and demo traffic' \
	  'make compose-down                  Stop all services and delete volumes' \
  'make zap-reports                   Copy latest ZAP md/html/json reports to zap/private/ (local only)' \
	  'make terraform-init                Initialize Terraform' \
	  'make terraform-plan                Package Lambda, initialize, validate and plan' \
	  'make terraform-apply               Package Lambda; Terraform builds image and deploys' \
	  'make terraform-output              Show deployment outputs' \
	  'make terraform-destroy             Destroy AWS resources after confirmation' \
	  'Default region: eu-central-1. Optional TFVARS=filename relative to aws/terraform.'

compose: compose-down
	@exec python3 aws/scripts/compose.py

zap-reports:
	@mkdir -p zap/private
	@for f in report.md report.html report.json; do docker compose cp zap:/zap/wrk/$$f zap/private/$$f; done
	@echo 'Raw reports contain URLs/evidence: keep local. Open zap/private/report.md or report.html'

compose-down:
	docker compose down -v --remove-orphans

package:
	sh aws/scripts/package.sh

terraform-init:
	terraform -chdir=aws/terraform init

terraform-plan terraform-apply: terraform-init package
	terraform -chdir=aws/terraform validate
	terraform -chdir=aws/terraform $(patsubst terraform-%,%,$@) $(TF_ARGS)

terraform-output:
	terraform -chdir=aws/terraform output

terraform-destroy: terraform-init
	terraform -chdir=aws/terraform destroy $(TF_ARGS)