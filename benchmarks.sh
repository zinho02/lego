#!/bin/bash
ROOT_DIR=$PWD
BENCHMARK_FOLDERS=(acme/api acme/api/internal/nonces acme/api/internal/secure acme/api/internal/sender certcrypto certificate challenge/http01 challenge/resolver cmd registration)
BENCHMARK_GOLANG_COMMAND='/home/zinho/go/src/github.com/zinho02/go/bin/go test -benchmem -benchtime 1x -run=^$ -bench=.'

for folder in ${BENCHMARK_FOLDERS[*]};
do
    cd $folder
    mkdir benchmarks
    touch benchmarks/results.txt
    $BENCHMARK_GOLANG_COMMAND > benchmarks/results.txt
    cd $ROOT_DIR
done