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
	shelltest --timeout=30 -cd tests/

.PHONY: gen-autocompletion
gen-autocompletion:
	cabal run mptcpanalyzer -- --bash-completion-script toto
