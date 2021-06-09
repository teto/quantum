#!/bin/sh

set -x
exe=$(cabal list-bin exe:mptcpanalyzer)
PATH="$(dirname $exe):$PATH"

replica run tests/*.json
