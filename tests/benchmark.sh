#!/bin/bash

BENCHMARK_OUT_DIR="/tmp/benchmark_output"

benchrun() {

    if [ ! -d "${BENCHMARK_OUT_DIR}" ]; then
        mkdir "${BENCHMARK_OUT_DIR}"
    fi
    ab -t 10 -c $1 -n $2 \
        -g "${BENCHMARK_OUT_DIR}/ga_$1_$2_run_$3.gnuplot" \
            -p xacml_request.xml \
            -H "Accept: application/xacml+xml" \
            http://127.0.0.1:8081/authorization/pdp/;
}

bench() {
    for ((i=1;i<=$3;i++)); do
        benchrun $1 $2 $i
        sleep 3
    done
    sleep 3
}

# Concurrency 1, total calls 100, amount of these runs 10
TRIES=10

bench   8  5000 ${TRIES}
bench  16  2000 ${TRIES}
bench  64  2000 ${TRIES}
bench 100  2000 ${TRIES}
bench  10 10000 ${TRIES}

