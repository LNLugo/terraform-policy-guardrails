# Local shortcuts. Requires opa and conftest on PATH (terraform for plan-*).
CONFTEST = conftest test --policy policy --data data --rego-version v1

.PHONY: test fixtures plan-compliant plan-noncompliant

test:            ## policy unit tests
	opa fmt --list --fail policy
	opa check --strict policy
	opa test policy -v

fixtures:        ## run the gate on the saved plan JSON files (no Terraform needed)
	$(CONFTEST) fixtures/plan-compliant.json
	-$(CONFTEST) fixtures/plan-noncompliant.json

plan-%:          ## real plan + gate, e.g. make plan-compliant
	cd terraform/$* && AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock TF_VAR_offline_plan=true \
	  terraform init -backend=false -input=false && \
	  terraform plan -input=false -out=tfplan && terraform show -json tfplan > ../../plan-$*.json
	$(CONFTEST) plan-$*.json
