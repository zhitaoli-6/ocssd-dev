#!/bin/bash

path=/mnt/debug

touch $path/f1

if [ $? -ne 0 ]; then
	exit 1
fi
mkdir $path/d1
if [ $? -ne 0 ]; then
	exit 1
fi

echo "f1" > $path/test_f

if [ $? -ne 0 ]; then
	exit 1
fi

