#!/usr/bin/python
#this is a python monitoring script to monitor dnsflow data being collected
#and sends an email update out

import os
import glob

dcap_directory = "/shannon/data2/dcap/base/dir" #edit me
update_time = 0 #midnight
mail_recipients = ["netrd@merit.edu"] 
dns_blacklist_dir = "/home/jkrez/code/workspace/dnsflow-tools/src/blacklists/"
ips_whitelist_dir = "/somewhere"
ignore_dirs = [".svn"]


blacklist_dns = {}
blacklist_ips = {}

#read dns blacklist list into dictionary
listing = os.listdir(dns_blacklist_dir)
for infile in listing:
	if os.path.isdir(dns_blacklist_dir+infile):
		continue
	print "opening file: %s" % infile
	fd = open(dns_blacklist_dir+infile, "r")
	#iterate over file
	line = fd.readline()
	while line:
		line = line.rstrip()
		print "read: |%s|" % line
		blacklist_dns[line] = 1 #enter into dict
		line = fd.readline()
	print "finished file %s" % infile

# other method for reading in file
#for infile in glob.glob( os.path.join(path, "*.ips") ):
#	<do stuff>

#read in ips blacklist into dictionary
listing = os.listdir(ips_blacklist_dir)
for infile in listing:
	if os.path.isdir(ips_blacklist_dir+infile):
		continue
	print "opening file: %s" % infile
	fd = open(ips_blacklist_dir+infile, "r")
	#iterate over file
	line = fd.readline()
	while line:
		line = line.rstrip()
		print "read: |%s|" % line
		blacklist_ips[line] = 1 #enter into dict
		line = fd.readline()
	print "finished file %s" % infile
print "done with all files"

