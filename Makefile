# TODO should be doable via LSP
stylish-haskell:
	stylish-haskell

.PHONY: hlint
lint:
	hlint

.PHONY: test
test:
	# TODO use shelltest https://github.com/simonmichael/shelltestrunner

.PHONY: gen-autocompletion
gen-autocompletion:
	cabal run mptcpanalyzer -- --bash-completion-script toto

