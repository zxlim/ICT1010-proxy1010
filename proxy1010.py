#!/usr/bin/env python3
# -*- coding: utf-8 -*-

########################################
# proxy1010.py
#
# For the partial fulfillment of the module
# ICT1010 Computer Networks, ICT Cluster,
# Singapore Institute of Technology.
#
# Assignment 2:
# Simple TCP-based HTTP Proxy Server.
#
# Group Members:
#    Ang Pei Hao         (1802945)
#    Dominic Keeley Gian (1802956)
#    Lim Zhao Xiang      (1802976)
#    Tan Chin How        (1802987)
########################################

import socket
import threading

from argparse import ArgumentParser
from select import select
from time import time


DEBUG = False

# Maximum size of buffer
BUF_SIZE = 4096

# Valid HTTP Request Methods.
HTTP_METHODS = ("CONNECT", "DELETE", "HEAD", "GET", "OPTIONS", "PATCH", "POST", "PUT", "TRACE")


def pretty_print(msg, level="info", debug_msg=False):
	"""
	Just another custom pretty print function.
	"""
	if debug_msg:
		# Message is classified as debug message.
		if DEBUG:
			# Only print debug messages if debug mode is enabled.
			if level == "info":
				print("[DEBUG][*] {0}".format(msg))
			elif level == "good":
				print("[DEBUG][+] {0}".format(msg))
			elif level == "warn":
				print("[DEBUG][-] {0}".format(msg))
			elif level == "error":
				print("[DEBUG][!] {0}".format(msg))
			else:
				print("[DEBUG][{0}] {1}".format(level, msg))
	else:
		if level == "info":
			print("[*] {0}".format(msg))
		elif level == "good":
			print("[+] {0}".format(msg))
		elif level == "warn":
			print("[-] {0}".format(msg))
		elif level == "error":
			print("[!] {0}".format(msg))


class HTTPConnection(object):
	"""
	HTTPConnection object.
	"""
	def __init__(self, conn_type):
		super(HTTPConnection, self).__init__()
		assert conn_type in ("client", "server")
		self.conn_type = None
		self.host = None
		self.port = None
		self.sock = None
		self.proto = None
		self.buf = b""
		self.timeout = int(time()) + 5

	def __repr__(self):
		return "<HTTPConnection : host={0}, port={1}, proto={2}, type={3}>".format(self.host, self.port, self.proto, self.conn_type)

	def __str__(self):
		return self.__repr__()

	def close(self):
		"""
		Close the socket.
		"""
		if self.sock:
			# Sanity check.
			try:
				self.sock.shutdown(socket.SHUT_RDWR)
			except socket.error:
				pass
			self.sock.close()
		self.sock = None

	def check_timeout(self):
		"""
		Returns the timeout status of the socket.
		"""
		if int(time()) > self.timeout:
			return True
		return False

	def buf_size(self):
		"""
		Returns the current buffer size.
		"""
		return len(self.buf)

	def buf_append(self, data):
		"""
		Append additional data to buffer.
		"""
		self.buf += data

	def recv(self):
		"""
		Receive and returns data from the socket.
		"""
		data = self.sock.recv(BUF_SIZE)
		if len(data) == 0:
			return None
		return data

	def __send(self, data):
		"""
		Send data via the socket.
		"""
		try:
			return self.sock.send(data)
		except:
			return 0

	def send_buf(self):
		"""
		Send whatever is in the buffer through the socket and updating
		the buffer with the remaining data that is not yet sent.
		"""
		size = self.__send(self.buf)
		self.buf = self.buf[size:]


class HTTPClient(HTTPConnection):
	"""
	HTTPClient object. Sub-class of HTTPConnection.
	"""
	def __init__(self, host, port, sock):
		super(HTTPClient, self).__init__("client")
		self.host = host
		self.port = port
		self.sock = sock

	def __del__(self):
		self.close()


class HTTPServer(HTTPConnection):
	"""
	HTTPServer object. Sub-class of HTTPConnection.
	"""
	def __init__(self, host, port, proto):
		super(HTTPServer, self).__init__("server")
		self.host = host
		self.port = port
		self.proto = proto

	def __del__(self):
		self.close()

	def connect(self):
		"""
		Establish a connection with the remote web server.
		"""
		self.sock = socket.create_connection((self.host, self.port))


class ProxyHandler(threading.Thread):
	"""
	ProxyHandler:

	This handler is in charge of proxying HTTP requests
	from a client to a specified server and then forwarding
	any responses back to the client.
	"""
	def __init__(self, client):
		super(ProxyHandler, self).__init__()
		self.client = client
		self.server = None

	def get_select_list(self):
		"""
		Function to dynamically generate the list for select.select().
		"""
		r_list, w_list, x_list = [self.client.sock], [], []

		if self.client.buf_size() > 0:
			self.client.timeout = int(time()) + 5
			w_list.append(self.client.sock)

		if self.server:
			self.server.timeout = int(time()) + 5
			r_list.append(self.server.sock)
			if self.server.buf_size() > 0:
				w_list.append(self.server.sock)

		return r_list, w_list, x_list

	def parse_request(self, data):
		"""
		Function to parse HTTP request data and retrieve the web server
		host (domain) and port, protocol (HTTP/ HTTPS) and the HTTP request method.
		"""
		host, port, proto = None, None, None

		req = str(data.decode("utf-8").strip()).split("\\r\\n")
		method = req[0].split(" ")[0].strip()
		remote_addr = req[0].split(" ")[1].strip()

		# Get the protocol. Some default port settings here.
		if remote_addr.startswith("http://"):
			port, proto = 80, "http"
			remote_addr = remote_addr.replace("http://", "")
		elif remote_addr.startswith("https://"):
			port, proto = 443, "https"
			remote_addr = remote_addr.replace("https://", "")

		if method.upper() not in HTTP_METHODS:
			# Unsupported or invalid HTTP method.
			pretty_print("Invalid HTTP method '{2}' from client [{0}:{1}]".format(self.client.host, self.client.port, method), "error")
			return None, None, None, None
		elif method.upper() == "CONNECT":
			# Start of HTTPS tunnel connection.
			proto = "https"
			host, port_str = remote_addr.split(":")

			try:
				port = int(port_str)
			except (TypeError, ValueError):
				# Default HTTPS port.
				port = 443
		else:
			domain = remote_addr.split("/")[0].strip()

			if ":" in domain:
				# Port specified in resource.
				host, port_str = domain.split(":")

				try:
					port = int(port_str)
				except (TypeError, ValueError):
					if not proto:
						port = 80

				if port == 443:
					proto = "https"
			else:
				host = domain
				if not proto:
					port, proto = 80, "http"

		if proto == "http":
			pretty_print("HTTP request received [{0}:{1}].".format(host, port), debug_msg=True)
		elif proto == "https":
			pretty_print("HTTPS request received [{0}:{1}].".format(host, port), debug_msg=True)

		return host, port, proto, method

	def handle_request(self, data):
		"""
		Function for handling HTTP requests.
		"""
		if self.server and self.server.sock:
			# Server connection already established; this is not a
			# "new request" but a "continuation" (E.g. chunked encoding?).
			self.server.buf_append(data)
			return True
		else:
			host, port, proto, method = self.parse_request(data)

			if not method:
				self.client.buf_append(b"\r\n".join([b"HTTP/1.1 400 Bad request", b"\r\n"]))
				return False

			self.client.proto = proto
			self.server = HTTPServer(host, port, proto)

			try:
				self.server.connect()
			except socket.error:
				pretty_print("Failed to connect to web server [{0}:{1}]".format(host, port), "error")
				self.server.close()
				return False

			if method.upper() == "CONNECT":
				# Request to open HTTP tunnel authorised.
				self.client.buf_append(b"\r\n".join([b"HTTP/1.1 200 OK", b"\r\n"]))
			else:
				# Add the data to the server socket buffer, prepare to send it to web server.
				self.server.buf_append(data)

		return True

	def run(self):
		"""
		Main thread function.
		"""
		while True:
			r_list, w_list, x_list = self.get_select_list()
			r, w, x = select(r_list, w_list, x_list, 10)

			# Prioritise sending data over receiving.
			if self.client.sock in w:
				# Writing data to client socket.
				self.client.send_buf()
			if self.server:
				if self.server.sock in w:
					# Writing data to server socket.
					self.server.send_buf()

			# Time to receive data.
			if self.client.sock in r:
				# Receiving data from client socket.
				data = self.client.recv()
				if not data:
					# EOF.
					break
				elif not self.handle_request(data):
					break
			if self.server:
				if self.server.sock in r:
					# Receiving data from server socket.
					data = self.server.recv()
					if not data:
						# EOF.
						break
					else:
						self.client.buf_append(data)

			# Enforce a timeout to prevent stale connections.
			if self.client.check_timeout():
				pretty_print("Client connection timeout.", "warn", debug_msg=True)
				break
			elif self.server and self.server.check_timeout():
				pretty_print("Server connection timeout.", "warn", debug_msg=True)
				break

		# Close the client and server socket.
		self.client.close()
		if self.server:
			self.server.close()
		pretty_print("Closing client connection [{0}:{1}]".format(self.client.host, self.client.port), "warn", debug_msg=True)


class ProxyServer(object):
	"""
	ProxyServer:

	Handles incoming client connections and creates a new handler
	for each individual HTTP client.
	"""
	def __init__(self, port, backlog):
		super(ProxyServer, self).__init__()
		self.__host = "0.0.0.0"
		self.__port = port
		self.__backlog = backlog
		self.__sock = None

	def terminate(self):
		if self.__sock:
			# Sanity check.
			try:
				self.__sock.shutdown(socket.SHUT_RDWR)
			except socket.error:
				pass
			self.__sock.close()
		self.__sock = None

	def run(self):
		try:
			self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
			self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.__sock.bind((self.__host, self.__port))
			self.__sock.listen(self.__backlog)
		except socket.error:
			pretty_print("Socket address already in use, try again in a few minutes time.", "error")
			return

		pretty_print("Proxy listening on {0}/tcp.".format(self.__port), "good")

		while True:
			cs, addr = self.__sock.accept()
			client = HTTPClient(addr[0], addr[1], cs)

			pretty_print("Client accepted [{0}:{1}]".format(*addr), "good", debug_msg=True)

			handler = ProxyHandler(client)
			handler.daemon = True
			handler.start()


def main():
	"""
	`python3 proxy1010.py -h` for usage instructions.
	"""
	parser = ArgumentParser(description="Proxy1010: Simple HTTP/HTTPS Proxy Server written in Python.")
	parser.add_argument("-p", "--port", type=int, default=9000, help="(int) The TCP port to listen on. Defaults to 9000.")
	parser.add_argument("-b", "--backlog", type=int, default=32, help="(int) The backlog of the socket; maximum client connections to accept. Defaults to 32.")
	parser.add_argument("-d", "--debug", action="store_true", default=False, help="Run in debug mode.")
	args = parser.parse_args()

	if args.port < 0 or args.port > 65535:
		pretty_print("Invalid port specified: {0}".format(args.port), "error")
		return
	elif args.debug:
		global DEBUG
		DEBUG = True
		pretty_print("Debug mode enabled.", "info", debug_msg=True)

	try:
		proxy = ProxyServer(args.port, args.backlog)
		proxy.run()
	except KeyboardInterrupt:
		# Catch interrupts nicely.
		print("\n") # New line to make things look nicer.
		pretty_print("Keyboard interrupt detected.", "warn", debug_msg=True)
	finally:
		pretty_print("Shutting down Proxy1010...")
		proxy.terminate()


if __name__ == "__main__":
	main()
