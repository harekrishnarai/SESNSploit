#!/bin/bash

# SESNSploit Test Infrastructure Deployment Script
# This script helps deploy the test infrastructure for SESNSploit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    local missing_deps=()
    
    if ! command_exists terraform; then
        missing_deps+=("terraform")
    fi
    
    if ! command_exists aws; then
        missing_deps+=("aws-cli")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        echo "Please install the missing dependencies and try again."
        echo ""
        echo "Installation instructions:"
        echo "- Terraform: https://learn.hashicorp.com/tutorials/terraform/install-cli"
        echo "- AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        print_error "AWS credentials not configured or invalid"
        echo "Please configure AWS credentials using 'aws configure' or environment variables."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Function to setup terraform variables
setup_variables() {
    print_status "Setting up Terraform variables..."
    
    if [ ! -f "terraform.tfvars" ]; then
        if [ -f "terraform.tfvars.example" ]; then
            cp terraform.tfvars.example terraform.tfvars
            print_warning "Created terraform.tfvars from example template"
            print_warning "Please edit terraform.tfvars and set your domain before continuing"
            
            # Check if the user wants to edit now
            read -p "Do you want to edit terraform.tfvars now? (y/n): " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                ${EDITOR:-vi} terraform.tfvars
            else
                print_error "Please edit terraform.tfvars and set your domain, then run this script again"
                exit 1
            fi
        else
            print_error "terraform.tfvars.example not found"
            exit 1
        fi
    else
        print_success "terraform.tfvars already exists"
    fi
    
    # Check if domain is still the example domain
    if grep -q "test.example.com" terraform.tfvars; then
        print_error "Please update the test_email_domain in terraform.tfvars with your actual domain"
        exit 1
    fi
}

# Function to initialize terraform
init_terraform() {
    print_status "Initializing Terraform..."
    
    if terraform init; then
        print_success "Terraform initialized successfully"
    else
        print_error "Failed to initialize Terraform"
        exit 1
    fi
}

# Function to plan terraform deployment
plan_terraform() {
    print_status "Creating Terraform plan..."
    
    if terraform plan -out=tfplan; then
        print_success "Terraform plan created successfully"
        
        echo ""
        print_warning "Review the plan above carefully before proceeding"
        read -p "Do you want to apply this plan? (y/n): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deployment cancelled by user"
            exit 0
        fi
    else
        print_error "Failed to create Terraform plan"
        exit 1
    fi
}

# Function to apply terraform
apply_terraform() {
    print_status "Applying Terraform configuration..."
    
    if terraform apply tfplan; then
        print_success "Infrastructure deployed successfully!"
        rm -f tfplan
    else
        print_error "Failed to apply Terraform configuration"
        exit 1
    fi
}

# Function to show post-deployment instructions
show_instructions() {
    print_success "Deployment completed!"
    echo ""
    echo "Next steps:"
    echo "1. Complete SES domain and email verification (check Terraform output)"
    echo "2. Test SESNSploit with the created infrastructure:"
    echo "   python3 main.py"
    echo ""
    echo "For detailed testing instructions, see TEST-INFRASTRUCTURE.md"
    echo ""
    
    # Show some key outputs
    print_status "Getting key resource information..."
    echo ""
    echo "SNS Topics:"
    terraform output -json sns_topics 2>/dev/null | jq -r 'to_entries[] | "  \(.key): \(.value)"' || echo "  (Run 'terraform output sns_topics' to see topic ARNs)"
    echo ""
    echo "SES Identities:"
    terraform output -json ses_identities 2>/dev/null | jq -r 'to_entries[] | "  \(.key): \(.value)"' || echo "  (Run 'terraform output ses_identities' to see identities)"
    echo ""
    echo "Test Roles:"
    terraform output -json iam_roles 2>/dev/null | jq -r 'to_entries[] | "  \(.key): \(.value)"' || echo "  (Run 'terraform output iam_roles' to see role ARNs)"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  deploy    - Deploy the test infrastructure (default)"
    echo "  destroy   - Destroy the test infrastructure"
    echo "  plan      - Show what would be deployed"
    echo "  output    - Show Terraform outputs"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 deploy   # Deploy infrastructure"
    echo "  $0 destroy  # Clean up infrastructure"
    echo "  $0 plan     # Preview changes"
}

# Function to destroy infrastructure
destroy_infrastructure() {
    print_warning "This will destroy ALL test infrastructure!"
    read -p "Are you sure you want to destroy the infrastructure? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Destroying infrastructure..."
        if terraform destroy -auto-approve; then
            print_success "Infrastructure destroyed successfully"
        else
            print_error "Failed to destroy infrastructure"
            exit 1
        fi
    else
        print_status "Destruction cancelled"
    fi
}

# Function to show terraform outputs
show_outputs() {
    print_status "Terraform outputs:"
    echo ""
    terraform output
}

# Main script logic
main() {
    echo "SESNSploit Test Infrastructure Deployment"
    echo "========================================"
    echo ""
    
    # Parse command line arguments
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            setup_variables
            init_terraform
            plan_terraform
            apply_terraform
            show_instructions
            ;;
        "destroy")
            check_prerequisites
            destroy_infrastructure
            ;;
        "plan")
            check_prerequisites
            setup_variables
            init_terraform
            terraform plan
            ;;
        "output")
            show_outputs
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
