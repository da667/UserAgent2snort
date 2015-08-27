#!/usr/bin/python
# Version 1.0
##Imports##
#Argparse for fancy cli args
#textwrap for a fancy help/description output

import argparse
import textwrap

#Initialize argparse and print the big ass description and help usage block if -h or --help is used

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''
                    UserAgent2snort.py
                Brought to you by ...
                    @da_667
                ---------------------
Generates HTTP user-agent snort rules from a list of user-agents.
Usage: UserAgent2snort.py -i <infile> -o <outfile> -s <sid>
Infile format:
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Outfile format:
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"; flow:to_server,established; content:"Mozilla/4.0 |28|compatible|3B| MSIE 6.0|3B| Windows NT 5.1|29|"; metadata: service http; sid:1000000; rev:1;)
'''))

#Infile, outfile, and sid arguments via ArgParse. All required.

parser.add_argument('-i', dest="infile", required=True,
                    help="The name of the file containing a list of Domains, One domain per line.")
parser.add_argument('-o', dest="outfile", required=True, help="The name of the file to output your snort rules to.")
parser.add_argument('-s', dest="sid", type=int, required=True,
                    help="The snort sid to start numbering incrementally at. This number should be between 1000000 and 2000000 (one million and two million).")
args = parser.parse_args()

#This is a small check to ensure -s is set to a valid value between one and two million - the local rules range.

if args.sid < 1000000:
    print "The Value for sid (-s) is less than 1000000. Valid sid range is 1000000 to 2000000 (one million to two million)"
    exit()
elif args.sid > 2000000:
    print "The Value for sid (-s) is greater than 2000000. Valid sid range is 1000000 to 2000000 (one million to two million)"
    exit()

#fout is the file we will be outputting our rules to.
#f is the file we will read a list of user agents from.
#This script iterates through each line (via the for line loop), creating a list for each line.
#we then convert the "(", ")" and ";" chars to their hex representation and encase them in pipe chars (snort rule syntax for hex encoding)
#then we actually generate the rule and write to file, afterwards incrementing the SID by one.


with open(args.outfile, 'w') as fout:
    with open(args.infile, 'r') as f:
        for line in f:
            useragent = line.rstrip()
            ruleua = useragent.replace('(', '|28|').replace(')', '|29|').replace(';', '|3B|')
            rule = ("alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:\"BLACKLIST USER-AGENT known malicious user-agent %s\"; flow:to_server,established; content:\"%s\"; http_header; metadata: service http; sid:%s; rev:1;)\n" % (useragent.replace('(', '').replace(')', '').replace(';', ''), ruleua, args.sid))
            print rule
            fout.write(rule)
            args.sid += 1
exit()
