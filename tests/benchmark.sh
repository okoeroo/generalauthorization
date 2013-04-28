#!/bin/bash

BENCHMARK_OUT_DIR="/tmp/benchmark_output"
TRIES=1
WAITSEC=5
TIMEOUT=30
#TARGET="http://127.0.0.1:8081/authorization/pdp/"
TARGET="http://172.16.65.1:8081/authorization/pdp/"
PREFIX="ga_threads_8"

PLOT_OPTION="using 9 smooth sbezier with lines"
TMPFILE="/tmp/tmp_plot_file.tmp"
PNG="xacml_ga_plot.png"
PLOTLINE=""
i=0


benchrun() {

    if [ ! -d "${BENCHMARK_OUT_DIR}" ]; then
        mkdir "${BENCHMARK_OUT_DIR}"
    fi
    ab -c $1 -n $2 \
        -g "${BENCHMARK_OUT_DIR}/${PREFIX}_$1_$2_run_$3.gnuplot" \
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
}

# Concurrency 1, total calls 100, amount of these runs 10

#bench    8  10000 ${TRIES}
#bench   16  20000 ${TRIES}
#bench   32  10000 ${TRIES}
#bench   64  10000 ${TRIES}
bench  128  100000 ${TRIES}
#bench  256  10000 ${TRIES}
#bench    8 100000 ${TRIES}
#bench    8 1000000 ${TRIES}


####### PLOT IT #######

cat > "$TMPFILE" <<End-of-message
set title "XACML GA tests"
set ylabel "response time (ms)"
set xlabel "request"
set terminal pngcairo size 1024,768 enhanced font 'Verdana,12'
set output '$PNG'
End-of-message

ls "${BENCHMARK_OUT_DIR}" | while read FILE; do
    i=`expr $i + 1`
    if [ $i -eq 1 ]; then
        echo -n "plot \"${BENCHMARK_OUT_DIR}/${FILE}\" $PLOT_OPTION" >> "$TMPFILE"
    else
        echo -n ", \"${BENCHMARK_OUT_DIR}/${FILE}\" $PLOT_OPTION" >> "$TMPFILE"
    fi
done
echo >> "$TMPFILE"

cat "$TMPFILE" | gnuplot
