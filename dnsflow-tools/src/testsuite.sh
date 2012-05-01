#!/bin/bash

function bail() {
echo "FAILED! Reason: $1"
echo "Client output left in $2"

popd > /dev/null
exit 1
}

function dnsflowcat_test()
{
	echo ""
	echo ""
	echo "Testing dnsflow_cat"
	echo ""

	tmp="tmp"

	catfile1=tests/cap1.dcap
	catfile2=tests/cap2.dcap

	# Test 1 ########################
	./dnsflow-cat $catfile2 > $tmp
	diff $catfile2 tmp -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 1"
		bail "dnsflow-cat single file" $tmp
	fi
	echo "	passed test 1"

	# Test 2 ########################
	./dnsflow-cat -c $catfile2 > $tmp
	diff $catfile2 tmp -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 2"
		bail "dnsflow-cat -c single file" $tmp
	fi
	echo "	passed test 2"

	# Test 3 ########################
	./dnsflow-cat -c $catfile1 $catfile2 > $tmp
	diff tests/cap1+2.dcap tmp -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 3"
		bail "dnsflow-cat -c two files" $tmp
	fi
	echo "	passed test 3"

	# Test 4 ########################
	./dnsflow-cat -c $catfile2 $catfile1 > $tmp
	diff tests/cap1+2.dcap tmp -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 4"
		bail "dnsflow-cat -c two files ordering" $tmp
	fi
	echo "	passed test 4"

	#remove tmp files
	rm -rf $tmp
}

function dnsflowprint_test()
{
	echo ""
	echo ""
	echo "Testing dnsflow_print"
	echo ""

	tmp="tmp"
	test_file=tests/cap1+2.dcap
	master=tests/print1+2.txt

	# Test 1 ########################
	cat $test_file | ./dnsflow-print -R - > $tmp
	diff $tmp $master -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 1"
		bail "dnsflow-print single file" $tmp
	fi
	echo "	passed test 1"

	# Test 2 ########################
	master=tests/print1+2stats.txt
	cat $test_file | ./dnsflow-print -R - -s > $tmp
	diff $tmp $master -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 2"
		bail "dnsflow-print single file w/ stats" $tmp
	fi
	echo "	passed test 2"

	# Test 3 ########################
	master=tests/print1+2statsp0.txt
	cat $test_file | ./dnsflow-print -R - -s -p0 > $tmp
	diff $tmp $master -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 3"
		bail "dnsflow-print single file w/ stats p0" $tmp
	fi
	echo "	passed test 3" 

	# Test 4 ########################
	master=tests/print1+2statsp1.txt
	cat $test_file | ./dnsflow-print -R - -s -p1 > $tmp
	diff $tmp $master -a >  /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 4"
		bail "dnsflow-print single file w/ stats p1" $tmp
	fi
	echo "	passed test 4"

	# Test 5 ########################
	master=tests/print1+2statsp2.txt
	cat $test_file | ./dnsflow-print -R - -s -p2 > $tmp
	diff $tmp $master -a > /dev/null

	# test
	if [ $? -ne 0 ]; then
		echo "	failed test 5"
		bail "dnsflow-print single file w/ stats p2" $tmp
	fi
	echo "	passed test 5"

	#remove tmp files
	rm -rf $tmp
}


function dnsflowfilter_test()
{
	echo ""
	echo ""
	echo "Testing dnsflow_filter"
	echo ""

	test_filters=( '"aip == 218.145.68.188"' '"aip == 72.247.210.89"' '"aip == 74.125.225.79"'
				'"dname == mail.google.com"' '"dname == google.com"' '"dname == com"' 
				'"dname == net"' '"dname == cnn.com"' )

	input=tests/cap1+2.dcap
	test_file=
	master=
	tmp=
	count=0

	#loop through all test filters
	for i in "${test_filters[@]}"
	do
		#gen test name
		tmp="tests/filter1+2.${count}.dcap.tmp"
		#test each filter
		cat $input | ./dnsflow-filter -f $i > $tmp
		#create master name
		master="tests/filter1+2.${count}.dcap"
		diff $tmp $master -a > /dev/null

		# check test
		if [ $? -ne 0 ]; then
			echo -n "	failed test 1" 
			bail "dnsflow-filter filter $count" $tmp
		fi
		echo -n "	passed test $count"
		echo "	with filter $i"

		#remove file
		rm -rf $tmp

		(( count++ ))

	done
}

# Build dnsflow
make

# Run each test

dnsflowcat_test

if [ $? -ne 0 ]; then
	echo "failed dnsflow-cat tests."
	return 1;
fi
echo "passed dnsflow-cat tests!"

dnsflowprint_test

if [ $? -ne 0 ]; then
	echo "failed dnsflow-print tests."
	return 1;
fi
echo "passed dnsflow-print tests!"

dnsflowfilter_test

if [ $? -ne 0 ]; then
	echo "failed dnsflow-filter tests."
	return 1;
fi
echo "passed dnsflow-filter tests!"

exit 0
