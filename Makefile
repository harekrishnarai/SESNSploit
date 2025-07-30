# Makefile for SESNSploit Test Infrastructure Management

.PHONY: help init plan deploy destroy clean test-tool outputs check-vars validate fmt docs

# Default target
help: ## Show this help message
	@echo "SESNSploit Test Infrastructure Management"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make deploy      # Deploy test infrastructure"
	@echo "  make test-tool   # Test SESNSploit against deployed infrastructure"
	@echo "  make destroy     # Clean up all resources"

# Variables
TERRAFORM_DIR = .
TFVARS_FILE = terraform.tfvars
TFVARS_EXAMPLE = terraform.tfvars.example

init: ## Initialize Terraform
	@echo "Initializing Terraform..."
	cd $(TERRAFORM_DIR) && terraform init

check-vars: ## Check if terraform.tfvars exists and is configured
	@if [ ! -f "$(TFVARS_FILE)" ]; then \
		echo "Creating $(TFVARS_FILE) from example..."; \
		cp $(TFVARS_EXAMPLE) $(TFVARS_FILE); \
		echo "⚠️  Please edit $(TFVARS_FILE) and set your domain before deploying!"; \
		exit 1; \
	fi
	@if grep -q "test.example.com" $(TFVARS_FILE); then \
		echo "⚠️  Please update test_email_domain in $(TFVARS_FILE) with your actual domain!"; \
		exit 1; \
	fi

validate: init ## Validate Terraform configuration
	@echo "Validating Terraform configuration..."
	cd $(TERRAFORM_DIR) && terraform validate

fmt: ## Format Terraform files
	@echo "Formatting Terraform files..."
	cd $(TERRAFORM_DIR) && terraform fmt

plan: check-vars init ## Create Terraform plan
	@echo "Creating Terraform plan..."
	cd $(TERRAFORM_DIR) && terraform plan

deploy: check-vars init ## Deploy test infrastructure
	@echo "Deploying test infrastructure..."
	cd $(TERRAFORM_DIR) && terraform apply -auto-approve
	@echo ""
	@echo "✅ Deployment completed!"
	@echo "📋 Next steps:"
	@echo "   1. Complete SES verification (check outputs below)"
	@echo "   2. Run 'make test-tool' to test SESNSploit"
	@echo ""
	@make outputs

deploy-interactive: check-vars init ## Deploy with interactive approval
	@echo "Deploying test infrastructure (interactive)..."
	cd $(TERRAFORM_DIR) && terraform apply

destroy: ## Destroy test infrastructure
	@echo "🚨 This will destroy ALL test infrastructure!"
	@echo "Are you sure? Press Ctrl+C to cancel, or Enter to continue..."
	@read
	cd $(TERRAFORM_DIR) && terraform destroy -auto-approve

destroy-interactive: ## Destroy with interactive approval
	@echo "Destroying test infrastructure..."
	cd $(TERRAFORM_DIR) && terraform destroy

outputs: ## Show Terraform outputs
	@echo "Terraform Outputs:"
	@echo "=================="
	@cd $(TERRAFORM_DIR) && terraform output

test-commands: ## Show test commands for SESNSploit
	@echo "SESNSploit Test Commands:"
	@echo "========================"
	@cd $(TERRAFORM_DIR) && terraform output -raw test_commands

verification-requirements: ## Show SES verification requirements
	@echo "SES Verification Requirements:"
	@echo "============================="
	@cd $(TERRAFORM_DIR) && terraform output -raw verification_requirements

test-tool: ## Test SESNSploit with deployed infrastructure
	@echo "Testing SESNSploit with deployed infrastructure..."
	@echo "Make sure you have completed SES verification first!"
	@echo ""
	@echo "Running SESNSploit..."
	python3 main.py

test-sns: ## Test SNS functionality specifically
	@echo "Testing SNS functionality..."
	@echo "Assuming SNS test role and running SESNSploit..."
	$(eval SNS_ROLE := $(shell cd $(TERRAFORM_DIR) && terraform output -raw iam_roles | jq -r '.sns_test_role'))
	@echo "Role ARN: $(SNS_ROLE)"
	aws sts assume-role --role-arn $(SNS_ROLE) --role-session-name SESNSploitSNSTest

test-ses: ## Test SES functionality specifically  
	@echo "Testing SES functionality..."
	@echo "Assuming SES test role and running SESNSploit..."
	$(eval SES_ROLE := $(shell cd $(TERRAFORM_DIR) && terraform output -raw iam_roles | jq -r '.ses_test_role'))
	@echo "Role ARN: $(SES_ROLE)"
	aws sts assume-role --role-arn $(SES_ROLE) --role-session-name SESNSploitSESTest

send-test-message: ## Send a test SNS message
	@echo "Sending test SNS message..."
	$(eval TOPIC_ARN := $(shell cd $(TERRAFORM_DIR) && terraform output -raw sns_topics | jq -r '.notifications'))
	aws sns publish --topic-arn $(TOPIC_ARN) --message "Test message from Makefile" --subject "SESNSploit Test"
	@echo "✅ Test message sent to: $(TOPIC_ARN)"

send-test-email: ## Send a test SES email
	@echo "Sending test SES email..."
	$(eval EMAIL_IDENTITY := $(shell cd $(TERRAFORM_DIR) && terraform output -raw ses_identities | jq -r '.noreply_email'))
	@echo "From: $(EMAIL_IDENTITY)"
	@read -p "Enter recipient email: " RECIPIENT; \
	aws ses send-email \
		--source $(EMAIL_IDENTITY) \
		--destination "ToAddresses=$$RECIPIENT" \
		--message "Subject={Data='SESNSploit Test Email'},Body={Text={Data='This is a test email sent from the SESNSploit test infrastructure.'}}"
	@echo "✅ Test email sent from: $(EMAIL_IDENTITY)"

clean: ## Clean up Terraform files
	@echo "Cleaning up Terraform files..."
	rm -f terraform.tfstate.backup
	rm -f .terraform.lock.hcl
	rm -f tfplan
	rm -rf .terraform/
	rm -f *.zip

status: ## Show current infrastructure status
	@echo "Infrastructure Status:"
	@echo "====================="
	@echo ""
	@echo "Terraform State:"
	@if [ -f "terraform.tfstate" ]; then \
		echo "  ✅ terraform.tfstate exists"; \
		echo "  📊 Resources in state: $$(cd $(TERRAFORM_DIR) && terraform show -json | jq '.values.root_module.resources | length' 2>/dev/null || echo 'unknown')"; \
	else \
		echo "  ❌ No terraform.tfstate found"; \
	fi
	@echo ""
	@echo "Configuration:"
	@if [ -f "$(TFVARS_FILE)" ]; then \
		echo "  ✅ $(TFVARS_FILE) exists"; \
		echo "  🌐 Domain: $$(grep '^test_email_domain' $(TFVARS_FILE) | head -1 | cut -d'"' -f2)"; \
		echo "  🌍 Primary Region: $$(grep '^primary_region' $(TFVARS_FILE) | head -1 | cut -d'"' -f2)"; \
	else \
		echo "  ❌ $(TFVARS_FILE) not found"; \
	fi

docs: ## Generate documentation
	@echo "Generating documentation..."
	@echo "📖 Available documentation:"
	@echo "  - README.md (main tool documentation)"
	@echo "  - TEST-INFRASTRUCTURE.md (infrastructure documentation)"
	@echo "  - attack-scenarios/README.md (attack scenarios)"
	@echo ""
	@echo "📋 Quick links:"
	@echo "  - Infrastructure setup: make deploy"
	@echo "  - Tool testing: make test-tool"
	@echo "  - Cleanup: make destroy"

# Advanced targets for development
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	@make check-vars
	@make init
	@make validate
	@make fmt
	@echo "✅ Development environment ready"

dev-cycle: ## Development cycle: format, validate, plan
	@echo "Running development cycle..."
	@make fmt
	@make validate
	@make plan

# Attack scenario targets
deploy-attack-scenarios: ## Deploy attack scenario infrastructure
	@echo "Deploying attack scenario infrastructure..."
	@cd attack-scenarios/attack-1-sns-topic-hijacking && terraform init && terraform apply -auto-approve
	@cd attack-scenarios/attack-2-ses-identity-spoofing && terraform init && terraform apply -auto-approve

destroy-attack-scenarios: ## Destroy attack scenario infrastructure
	@echo "Destroying attack scenario infrastructure..."
	@cd attack-scenarios/attack-1-sns-topic-hijacking && terraform destroy -auto-approve || true
	@cd attack-scenarios/attack-2-ses-identity-spoofing && terraform destroy -auto-approve || true

# Multi-environment support
deploy-minimal: ## Deploy minimal test environment
	@echo "Deploying minimal test environment..."
	@cd $(TERRAFORM_DIR) && terraform apply -auto-approve -var="create_cross_region_resources=false" -var="create_vulnerable_configs=false"

deploy-full: ## Deploy full test environment with all features
	@echo "Deploying full test environment..."
	@cd $(TERRAFORM_DIR) && terraform apply -auto-approve -var="create_cross_region_resources=true" -var="create_vulnerable_configs=true"

# Monitoring and debugging
logs: ## Show recent CloudTrail logs (if available)
	@echo "Recent AWS API calls (last 1 hour):"
	aws logs filter-log-events \
		--log-group-name CloudTrail/SESNSploitTest \
		--start-time $$(date -d '1 hour ago' +%s)000 \
		--filter-pattern "{ $.eventSource = sns.amazonaws.com || $.eventSource = ses.amazonaws.com }" \
		2>/dev/null || echo "No CloudTrail logs found (this is normal for test environments)"

health-check: ## Check if deployed resources are healthy
	@echo "Checking resource health..."
	@echo ""
	@echo "SNS Topics:"
	@cd $(TERRAFORM_DIR) && terraform output -json sns_topics 2>/dev/null | jq -r 'to_entries[] | "  Checking \(.key): \(.value)"' | while read line; do \
		echo "$$line"; \
		TOPIC_ARN=$$(echo "$$line" | awk '{print $$NF}'); \
		aws sns get-topic-attributes --topic-arn $$TOPIC_ARN >/dev/null 2>&1 && echo "    ✅ Accessible" || echo "    ❌ Not accessible"; \
	done
	@echo ""
	@echo "SES Identities:"
	@cd $(TERRAFORM_DIR) && terraform output -json ses_identities 2>/dev/null | jq -r 'to_entries[] | "  \(.key): \(.value)"' | while read line; do \
		echo "$$line"; \
	done
