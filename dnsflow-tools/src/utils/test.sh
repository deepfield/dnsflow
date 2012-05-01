#!/bin/bash

#tests hash function look up vs string comp at various sizes

max_string_len=1500000
current_len=1

rm hashtest.txt -rf
echo "string							hash							diff" >> hashtest.txt

while [ $current_len -lt $max_string_len ]; do
	#string=$( perl -e "print '"x"' x $current_len"	)
	echo "Running hash with size $current_len"
	./hash $current_len >> hashtest.txt
	current_len=$(($current_len*2))
done
