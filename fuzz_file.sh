#!/bin/bash

OUTFILE=${1}.fuzzed

for i in `seq -w 01 1 99`; do
 dd if=$1 of=fuzz.block.$RANDOM skip=$RANDOM bs=$((RANDOM/256)) count=$((RANDOM/256)) > /dev/null 2> /dev/null
done

cat fuzz.block.* > $OUTFILE

rm fuzz.block.*
