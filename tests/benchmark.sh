#!/bin/bash

BENCHMARK_OUT_DIR="/tmp/benchmark_output"
TRIES=1
WAITSEC=5
TIMEOUT=30

usage() {
    echo "Use: benchmark.sh <xml|xmljson|jsonxml|json> [host]"
}

if [ -z "$1" ]; then
    usage
    exit 1
fi


if [ "json" = "$1" ]; then
    accept="Accept: application/xacml+json"
    contenttype="application/xacml+json"
    requestfile="xacml_request.json"

    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8081"
    URI="authorization/pdp/"
    METHOD="POST"
elif [ "xmljson" = "$1" ]; then
    accept="Accept: application/xacml+json"
    contenttype="application/xacml+xml"
    requestfile="xacml_request.xml"

    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8081"
    URI="authorization/pdp/"
    METHOD="POST"
elif [ "jsonxml" = "$1" ]; then
    accept="Accept: application/xacml+xml"
    contenttype="application/xacml+json"
    requestfile="xacml_request.json"

    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8081"
    URI="authorization/pdp/"
    METHOD="POST"
elif [ "xml" = "$1" ]; then
    accept="Accept: application/xacml+xml"
    contenttype="application/xacml+xml"
    requestfile="xacml_request.xml"

    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8081"
    URI="authorization/pdp/"
    METHOD="POST"
elif [ "control" = "$1" ]; then
    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8080"
    URI="control/"
    METHOD="GET"
elif [ "pap" = "$1" ]; then
    PROTOCOL="http"
    HOST=${2:-localhost}
    PORT="8080"
    URI="authorization/pap/"
    METHOD="GET"
else
    usage
    exit 1
fi

TARGET="${PROTOCOL}://${HOST}:${PORT}/${URI}"

echo "Target set to: ${TARGET}"

PREFIX="ga_threads_16"

PLOT_OPTION="using 9 smooth sbezier with lines"
TMPFILE="/tmp/tmp_plot_file.tmp"
PNG="xacml_ga_plot.png"
PLOTLINE=""


thresholding() {
    THRESHOLD=20;
    while [ true ]; do
        TWCNT=$(netstat -na | grep TIME_WAIT | wc -l);
        if [ $TWCNT -lt $THRESHOLD ]; then
            break;
        else
            echo "Still seeing $TWCNT TIME_WAIT. Waiting until less then $THRESHOLD";
            sleep 3;
        fi;
    done
}

benchrun() {
    thresholding

    if [ ! -d "${BENCHMARK_OUT_DIR}" ]; then
        mkdir "${BENCHMARK_OUT_DIR}"
    fi

    echo "== Now setting up == Concurrency: $1 Number of requests $2 in Try $3 on Target $TARGET using $METHOD and output in ${BENCHMARK_OUT_DIR}/${PREFIX}_$1_$2_run_$3.gnuplot"
    if [ "$METHOD" = "POST" ]; then
        ab -r -c $1 -n $2 \
            -g "${BENCHMARK_OUT_DIR}/${PREFIX}_$1_$2_run_$3.gnuplot" \
                -p "$requestfile" \
                -H "$accept" \
                -T "$contenttype" \
                "${TARGET}";
    elif [ "$METHOD" = "POST" ]; then
        ab -r -c $1 -n $2 \
            -g "${BENCHMARK_OUT_DIR}/${PREFIX}_$1_$2_run_$3.gnuplot" \
                "${TARGET}";
    fi
}

bench() {
    for ((i=1;i<=$3;i++)); do
        benchrun $1 $2 $i
        echo "Waiting ${WAITSEC} seconds"
        sleep ${WAITSEC}
    done
}

# Concurrency 1, total calls 100, amount of these runs 10
bench    4 1000   ${TRIES}

bench    4 100000 ${TRIES}
bench    8 100000 ${TRIES}
bench   16 100000 ${TRIES}
bench   32 100000 ${TRIES}
bench   64 100000 ${TRIES}
bench  128 100000 ${TRIES}
bench  256 100000 ${TRIES}
bench  512 100000 ${TRIES}
bench 1024 100000 ${TRIES}
bench 2048 100000 ${TRIES}


####### PLOT IT #######

cat > "$TMPFILE" <<End-of-message
set title "XACML GA tests"
set ylabel "response time (ms)"
set xlabel "request"
set terminal pngcairo size 1366,900 enhanced font 'Verdana,11'
set output '$PNG'
End-of-message

i=0
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
