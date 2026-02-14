.PHONY: test lint lint-fix

GOCMD:=go
GOTEST:=$(GOCMD) test

# test runs all tests
test:
	$(GOTEST) -timeout 30m -p 1 $$(go list ./... | grep -v "vendor/")

# lint runs all linters
lint:
ifeq (, $(shell which golangci-lint))
	$(error "could not find golangci-lint in $(PATH), see: https://golangci-lint.run/docs/welcome/install/local for installation instructions")
else
	$(info ******************** running lint tools ********************)
	@golangci-lint run ./...
endif


# lint-fix runs all linters and fixes all fixable issues
lint-fix:
ifeq (, $(shell which golangci-lint))
	$(error "could not find golangci-lint in $(PATH), see: https://golangci-lint.run/docs/welcome/install/local for installation instructions")
else
	$(info ******************** running lint tools and fixing issues ********************)
	golangci-lint run ./... --fix
endif
