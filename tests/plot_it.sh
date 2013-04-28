#!/bin/bash

DIR="/tmp/benchmark_output"
PLOT_OPTION="using 9 smooth sbezier with lines"
TMPFILE="/tmp/tmp_plot_file.tmp"

PNG="xacml_ga_plot.png"

PLOTLINE=""
i=0

cat > "$TMPFILE" <<End-of-message
set title "XACML GA tests"
set ylabel "response time (ms)"
set xlabel "request"
set terminal pngcairo size 1366,900 enhanced font 'Verdana,12'
set output '$PNG'
End-of-message

ls ${DIR}/ga_threads_{8,16,32}_256*  | while read FILE; do
    i=`expr $i + 1`
    if [ $i -eq 1 ]; then
        echo -n "plot \"${FILE}\" $PLOT_OPTION" >> "$TMPFILE"
    else
        echo -n ", \"${FILE}\" $PLOT_OPTION" >> "$TMPFILE"
    fi
done
echo >> "$TMPFILE"

cat "$TMPFILE"

cat "$TMPFILE" | gnuplot
