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
test: build
	# TODO use shelltest https://github.com/simonmichael/shelltestrunner
	# TODO adjust command
	# shelltest --timeout=30 -cd tests/
	replica run tests/*.json

.PHONY: gen-autocompletion
gen-autocompletion:
	cabal run mptcpanalyzer -- --bash-completion-script toto

gen-tests:
	dhall-to-json --file tests/hello.dhall --output tests/hello.json

