

TEST_FILES ?= tests/hello.json

# TODO should be doable via LSP/test ormolu
stylish-haskell:
	stylish-haskell

.PHONY: hlint
hlint:
	hlint

configure:
	cabal configure

build:
	cabal build

.PHONY: test
test: build $(TEST_FILES)
	# TODO use shelltest https://github.com/simonmichael/shelltestrunner
	# TODO adjust command
	# shelltest --timeout=30 -cd tests/
	# TODO run $(TEST_FILES)
	replica run tests/*.json

.PHONY: gen-autocompletion
gen-autocompletion:
	cabal run mptcpanalyzer -- --bash-completion-script toto


%.json: %.dhall
	dhall-to-json --file $< --output $@

# $(TEST_FILES):
	# -v ${PWD}/build/doc/$(@F):/docs/build/html/ $(subst _,-,$(@F)) poetry run sh -c \

	# dhall-to-json --file tests/$(basename @F).dhall --output tests/$(@F).json

# gen-tests:
# 	dhall-to-json --file tests/hello.dhall --output tests/hello.json

