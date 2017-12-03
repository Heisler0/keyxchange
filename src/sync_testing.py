from keyexchange import *
import _thread
import sys
from time import sleep

num_threads = 0

class KE_Mock(object):
	def __init__(self, port, server=1):
		self.server = server
		self.port = port

	def run(self):
		global num_threads
		num_threads += 1
		if self.server:
			KE_Server(self.port).mainloop()
		else:
			KE_Client(self.port).mainloop()
		num_threads -= 1

class KE_Driver(object):
	def __init__(self, port, max_clients=1):
		self.port = port
		self.max_clients = max_clients

	def run(self):
		global num_threads
		self.server()
		self.clients()
		while num_threads > 0:
			sleep(1)

	def server(self):
		print("Server")
		s_lock = _thread.allocate_lock()
		server = KE_Mock(self.port)
		_thread.start_new_thread(server.run, ())
		print(s_lock.acquire())
		sleep(0.1)
	
	def clients(self):
		for i in range(self.max_clients):
			print("Client " + str(i))
			c_lock = _thread.allocate_lock()
			client = KE_Mock(self.port, 0)
			_thread.start_new_thread(client.run, ())
			print(c_lock.acquire())
			sleep(0.1)


tester = KE_Driver(int(sys.argv[1]))
tester.run()
print("End Test")			
