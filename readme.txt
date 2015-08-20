UserAgent2snort.py
-by da_667
-with code contributions from @botnet_hunter and @3XPlo1T2

Purpose: Given a file containing a list of HTTP user-agents, generate snort rules for those HTTP user-agents. Incredibly useful if you are sitting on top of a pile of IOCs, but want an efficiently lazy way to generate snort sigs for them.
Requires: argparse, textwrap, python 2.7
Tested on: OSX, Ubuntu, Debian

Options (all fields except -h are required!):
-i : input file. Point the script to the file that contains the list of user-agents (one user-agent per line)
-o : output file: File to output your new snort rules
-s : SID. This is integer value that must be between 1000000 and 2000000 (one million and two million)
-h : prints out the most badass help message you've ever seen.

Provided with this script is a sample user-agents list, as well as a sample.rules to show you what the results would look like after execution:

Opera/9.30 (Nintendo Wii; U; ; 2047-7; en)
wii libnup/1.0
Java/1.6.0_13
libwww-perl/5.820
Peach/1.01 (Ubuntu 8.04 LTS; U; en)
Python-urllib/2.5
HTMLParser/1.6
Jigsaw/2.2.5 W3C_CSS_Validator_JFouffa/2.0

..becomes:

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Opera/9.30 (Nintendo Wii; U; ; 2047-7; en)"; flow:to_server,established; content:"Opera/9.30 |28|Nintendo Wii|3B| U|3B| |3B| 2047-7|3B| en|29|"; http_header; metadata: service http; sid:1000000; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent wii libnup/1.0"; flow:to_server,established; content:"wii libnup/1.0"; http_header; metadata: service http; sid:1000001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Java/1.6.0_13"; flow:to_server,established; content:"Java/1.6.0_13"; http_header; metadata: service http; sid:1000002; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent libwww-perl/5.820"; flow:to_server,established; content:"libwww-perl/5.820"; http_header; metadata: service http; sid:1000003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Peach/1.01 (Ubuntu 8.04 LTS; U; en)"; flow:to_server,established; content:"Peach/1.01 |28|Ubuntu 8.04 LTS|3B| U|3B| en|29|"; http_header; metadata: service http; sid:1000004; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Python-urllib/2.5"; flow:to_server,established; content:"Python-urllib/2.5"; http_header; metadata: service http; sid:1000005; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent HTMLParser/1.6"; flow:to_server,established; content:"HTMLParser/1.6"; http_header; metadata: service http; sid:1000006; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST USER-AGENT known malicious user-agent Jigsaw/2.2.5 W3C_CSS_Validator_JFouffa/2.0"; flow:to_server,established; content:"Jigsaw/2.2.5 W3C_CSS_Validator_JFouffa/2.0"; http_header; metadata: service http; sid:1000007; rev:1;)


These are all properly formatted snort rules ready to be pushed to a sensor. (Please note that none of these user agents are malicious. They were harvested from the user agent switcher user agent list: http://techpatterns.com/downloads/firefox/useragentswitcher.xml)
Note: The user agents list should not have ANY trailing spaces on any of the individual user-agent lines. Additionally, there should be ZERO blank lines in the user-agent file that will be used to generate the snort rules.