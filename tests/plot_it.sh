#!/bin/bash

DIR="/tmp/benchmark_output"
OPTION="using 9 smooth sbezier with lines"
TMPFILE="/tmp/tmp_plot_file.tmp"

PNG="xacml_ga_plot.png"

PLOTLINE=""
i=0

cat > "$TMPFILE" <<End-of-message
set title "XACML GA tests"
set ylabel "response time (ms)"
set xlabel "request"
set terminal pngcairo size 1024,768 enhanced font 'Verdana,12'
set output '$PNG'
End-of-message

ls "${DIR}" | while read FILE; do
    i=`expr $i + 1`
    if [ $i -eq 1 ]; then
        echo -n "plot \"${DIR}/${FILE}\" $OPTION" >> "$TMPFILE"
    else
        echo -n ", \"${DIR}/${FILE}\" $OPTION" >> "$TMPFILE"
    fi
done
echo >> "$TMPFILE"

cat "$TMPFILE"

cat "$TMPFILE" | gnuplot
