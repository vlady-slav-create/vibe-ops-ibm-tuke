.DEFAULT_GOAL := help

TFVARS ?=
TF_ARGS = $(if $(TFVARS),-var-file="$(TFVARS)")
ifneq ($(strip $(AWS_PROFILE)),)
export AWS_PROFILE
endif
COMPOSE_PROFILES ?=
export COMPOSE_PROFILES

.PHONY: help compose compose-down package terraform-init terraform-plan terraform-apply terraform-output terraform-destroy

help:
	@printf '%s\n' \
	  'make compose                       Stop containers, then rebuild and start local pipeline' \
	  'make compose COMPOSE_PROFILES=aws  Assume deployed publisher role and start pipeline' \
	  'make compose-down                  Stop all services; preserve volumes' \
	  'make terraform-init                Initialize Terraform' \
	  'make terraform-plan                Package Lambda, initialize, validate and plan' \
	  'make terraform-apply               Package Lambda; Terraform builds image and deploys' \
	  'make terraform-output              Show deployment outputs' \
	  'make terraform-destroy             Destroy AWS resources after confirmation' \
	  'Default region: eu-central-1. Optional TFVARS=filename relative to aws/terraform.'

compose:
	@set -eu; \
	case ",$$COMPOSE_PROFILES," in \
	  *,aws,*) \
	    exec python3 aws/scripts/compose.py; \
	    ;; \
	esac; \
	docker compose --profile aws down --remove-orphans; \
	docker compose up -d --build

compose-down:
	docker compose --profile aws down --remove-orphans

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