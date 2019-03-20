#!/usr/bin/env python3
# -*- coding: utf-8 -*-

########################################
#	For the partial fulfillment of the module
#	ICT1010 Computer Networks, ICT Cluster,
#	Singapore Institute of Technology.
#
#	Assignment 2:
#	Simple HTTP Proxy.
#
#	Group Members:
#	Ang Pei Hao			(1802945)
#	Dominic Keeley Gian	(1802956)
#	Lim Zhao Xiang		(1802976)
#	Tan Chin How		(1802987)
########################################

import socket
import traceback

from argparse import ArgumentParser
from select import select


# Set to True to print debug messages.
DEBUG = False


def print_debug(msg):
	if DEBUG:
		print("[DEBUG] {0}".format(msg))


class ProxyServer():
	def __init__(self, port):
		self.port = port
		self.sock = self.get_sock()


	def get_sock(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			sock.bind(("0.0.0.0", self.port))
		except socket.error:
			print("[!] Socket address already in use, try again in a few minutes time.")
			return None
		sock.listen(24)
		return sock


	def terminate(self):
		try:
			# Sanity check.
			if self.sock:
				self.sock.close()
			return True
		except Exception as e:
			if DEBUG:
				print("[!] Exception caught: {0}".format(e))
				traceback.print_exc()
			return False


	def check_request_end(self, data):
		if data.endswith(b"\r\n\r\n") or data.endswith(b"\r\n\r\n[]"):
			return True
		elif len(data) < 4:
			return True
		return False


	def get_remote_addr(self, client_request):
		host, port = None, 80

		url = str(client_request).split("\\r\\n")[0].split(" ")[1].replace("http://", "").split("/")[0].strip().split(":")

		host =  url[0]

		if len(url) == 2:
			port = int(url[1].strip())

		# Hacky way to drop HTTPS connections.
		if "https://" in str(client_request)[0] or port == 443:
			return None, None

		return host, port


	def proxy_request(self, request, remote_addr, remote_port):
		buf, fragments = None, []

		# Socket for connecting to remote web server.
		remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote.connect((remote_addr, remote_port))
		remote.send(request)

		try:
			while True:
				data = remote.recv(65535)

				if len(data) > 0:
					fragments.append(data)
					if self.check_request_end(data):
						break
				else:
					break
			if len(fragments) != 0:
				buf = b"".join(fragments)
		except Exception as e:
			if DEBUG:
				print("[!] Exception caught: {0}".format(e))
				traceback.print_exc()

		try:
			remote.shutdown(socket.SHUT_RDWR)
		except:
			pass
		finally:
			remote.close()
			print_debug("Closed remote connection.")

		return buf


	def run(self):
		if not self.sock:
			return 1

		print("[+] Web Proxy listening on {0}/tcp.".format(self.port))

		try:
			while True:
				r, w, x = select([self.sock], [], [])

				for s in r:
					if s is self.sock:
						# New connection.
						request, response, client, remote = None, None, None, None
						client, addr = self.sock.accept()

						print("[+] {0} ({1}/tcp): Client connected.".format(addr[0], addr[1]))

						try:
							request = client.recv(65535)
						except Exception as e:
							print("[!] Exception caught: {0}".format(e))
							traceback.print_exc()

						if request is not None:
							remote_addr, remote_port = self.get_remote_addr(request)

							if not remote_addr or not remote_port:
								print("[+] {0} ({1}/tcp): Dropping unsupported secure connection".format(addr[0], addr[1]))
							else:
								print("[+] {0} ({1}/tcp): Requested for [{2}:{3}]".format(addr[0], addr[1], remote_addr, remote_port))
								response = self.proxy_request(request, remote_addr, remote_port)

								if response is not None:
									print_debug("Sending response...")
									client.send(response)

						# Close the connection.
						try:
							client.shutdown(socket.SHUT_RDWR)
						except:
							pass
						finally:
							client.close()
							print_debug("Closed client connection.")
		except KeyboardInterrupt:
			print("\n[!] Interrupt key detected.")
		except Exception as e:
			if DEBUG:
				print("[!] Exception caught: {0}".format(e))
				traceback.print_exc()
			return 1
		finally:
			self.terminate()
			print("[*] Exiting...")
		return 0


def parse_arguments():
	parser = ArgumentParser(description="Simple HTTP Proxy written in Python. No support for HTTPS connections.")
	parser.add_argument("-p", "--port", type=int, default=8080, help="The port to listen on. Listens on 8080/tcp by default.")
	return parser.parse_args()


def main():
	args = parse_arguments()

	if args.port < 0 or args.port > 65535:
		print("[!] Invalid port specified: {0}".format(args.port))
		return 1
	
	proxy = ProxyServer(args.port)
	proxy.run()


if __name__ == "__main__":
	main()
