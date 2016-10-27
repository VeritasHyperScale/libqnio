#!/bin/bash

if [ $# -ne 2 ]
then
    echo "Usage: create_vdisk <filename> <size in MB>"
    exit
fi

file=$1
size=$2
touch $file
ddseek=`expr $size - 1`
echo $ddseek
dd if=/dev/zero of=$file bs=1M seek=$ddseek count=1 >/dev/null 2>&1
echo "created $file with size $size MB"
