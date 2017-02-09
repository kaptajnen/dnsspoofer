#!/usr/bin/python

import socket, dns.rdatatype, sys
from dns.message import from_wire, make_response
from dns.rrset import from_text
from dns.resolver import Resolver
from argparse import ArgumentParser

def get_response(data, spoofs, spoof_all):
	message = from_wire(data)
	domain = str(message.question[0].name)[:-1]
	rrset = None
	response = make_response(message)
	if spoofs and message.question[0].rdtype == dns.rdatatype.A and domain in spoofs:
		print('Spoofing query for %s' % domain)
		rrset = from_text(message.question[0].name, 300, dns.rdataclass.IN, dns.rdatatype.A, spoofs[domain])
	elif spoof_all and message.question[0].rdtype == dns.rdatatype.A:
		print('Spoofing query for %s due to spoof all' % domain)
		rrset = from_text(message.question[0].name, 300, dns.rdataclass.IN, dns.rdatatype.A, spoof_all)
	else:
		print('Not spoofing %s query for %s' % (dns.rdatatype.to_text(message.question[0].rdtype), domain))
		resolver = Resolver()
		rrset = resolver.query(message.question[0].name, message.question[0].rdtype, message.question[0].rdclass).rrset

	response.answer.append(rrset)

	return response


if __name__ == '__main__':
	parser = ArgumentParser(description='Run a DNS server with the ability spoof domains')
	parser.add_argument('-s', action='append', nargs=2, help='Domain and what IP it should point to', metavar=('domain', 'IP'))
	parser.add_argument('-a', help='Make any domain not specified with -s point to this IP instead of being looked up normally', metavar='IP')

	if len(sys.argv) > 1:
		args = parser.parse_args()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('',53))

		try:
			while True:
				data, address = s.recvfrom(1024)
				if args.s:
					spoofs = dict(args.s)
				else:
					spoofs = None
				response = get_response(data, spoofs, args.a)
				s.sendto(response.to_wire(), address)


		except KeyboardInterrupt:
			s.close()
	else:
		parser.print_help()
