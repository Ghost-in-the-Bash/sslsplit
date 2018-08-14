#!/usr/bin/env python3

import sys
import json

TCP = 1
SSL = 2
HTTP = 80
HTTPS = 443

protocols = {
	TCP: "tcp",
	SSL: "ssl",
	HTTP: "http",
	HTTPS: "https"
}

session = {
	"protocol": None,
	"src_ip"  : None,
	"src_port": None,
	"dst_ip":   None,
	"dst_port": None
}

protocol = 0

def read_addresses(addresses, connection):
	connection["src_ip"]   = addresses[1]
	connection["src_port"] = addresses[2]
	connection["dst_ip"]   = addresses[3]
	connection["dst_port"] = addresses[4]

def print_session(connection, protocol_n):
	connection["protocol"] = protocols[protocol_n]
	print(json.dumps(connection))
	if "host" in connection:
		del connection["host"]
	if "referer" in connection:
		del connection["referer"]

for line in sys.stdin.buffer:
	words = line.decode("utf8", "ignore").strip().split()
	head = ""

	if words:
		head = words[0].lower()

		if head == "tcp" and len(words) > 4:
			protocol = TCP
			read_addresses(words, session)

		elif head == "ssl" and len(words) > 4:
			protocol = SSL
			read_addresses(words, session)

		elif head == "host:" and len(words) > 1:
			session["host"] = words[1]

		elif head == "referer:" and len(words) > 1:
			session["referer"] = words[1]

		elif head == "</headers>" and protocol in {HTTP, HTTPS}:
			print_session(session, protocol)

		elif protocol not in {HTTP, HTTPS}:
			for word in words:
				if len(word) > 3 and word[0:4].lower() == "http":
					if protocol == SSL:
						protocol = HTTPS
					else:
						protocol = HTTP

sys.stdin.flush()
