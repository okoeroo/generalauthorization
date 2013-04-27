#!/bin/bash

BENCHMARK_OUT_DIR="/tmp/benchmark_output"
TRIES=1
WAITSEC=5
TIMEOUT=30
#TARGET="http://127.0.0.1:8081/authorization/pdp/"
TARGET="http://172.16.65.1:8081/authorization/pdp/"

benchrun() {

    if [ ! -d "${BENCHMARK_OUT_DIR}" ]; then
        mkdir "${BENCHMARK_OUT_DIR}"
    fi
    ab -c $1 -n $2 \
        -g "${BENCHMARK_OUT_DIR}/ga_$1_$2_run_$3.gnuplot" \
            -p xacml_request.xml \
            -H "Accept: application/xacml+xml" \
            "${TARGET}";
}

bench() {
    for ((i=1;i<=$3;i++)); do
        benchrun $1 $2 $i
        echo "Waiting ${WAITSEC} seconds"
        sleep ${WAITSEC}
    done
    echo "Waiting ${WAITSEC} seconds"
    sleep ${WAITSEC}
}

# Concurrency 1, total calls 100, amount of these runs 10

bench   8   5000 ${TRIES}
bench  16   5000 ${TRIES}
#bench  16   2000 ${TRIES}
#bench  64   2000 ${TRIES}
#bench 100   2000 ${TRIES}
#bench   8 100000 ${TRIES}
#bench   8 1000000 ${TRIES}

