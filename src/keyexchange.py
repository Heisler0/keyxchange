import numpy as np
import socket
from threading import Thread
import json
import binascii
from hashlib import sha256
import time

KE_CONFIRMATION_CODE = 111
KE_KEY_FOUND = 222
KE_ERROR = 333
#Buff size
KE_BUFF = 256
#Key sizei
# L
KE_SIZE = 4
#Key length is 128 bits, each int is 8 bits, length is number of ints to a weight/input vector
# N
KE_LENGTH = 4
#Number of layers
# K
KE_LAYERS = 10
#Number to sync
KE_SYNC = 1000

def KE_Dot(a, b):
	g = 0
	for i in range(KE_LENGTH):
		g = g + (a[i] * b[i])
	return g

def KE_Sign(n):
	return 1 if n >= 0 else -1

def KE_RandVector():
	x = np.random.randint(-KE_SIZE, KE_SIZE, size=KE_LENGTH).tolist() 
	y = np.random.randint(2, size=KE_LENGTH).tolist()
	for i in range(len(y)):
		x[i] *= KE_Sign(y[i])
	return x

def KE_RandSet():
	r = []
	for i in range(KE_LAYERS):
		r.append(KE_RandVector())
	return r

def KE_Add(w, x):
	result = []
	for i in range(KE_LENGTH):
		r = w[i] + x[i]
		if r > KE_SIZE:
			r = 4
		elif r < -KE_SIZE:
			r = -4
		
		result.append(r)
	return result

def KE_Learn(w, x, t):
	result = []
	for i in range(KE_LAYERS):
		if t==KE_Sign(KE_Dot(w[i], x[i])):
			result.append(KE_Add(w[i], x[i])) 
		else:
			result.append(w[i])
		
	return result

def KE_Train(w, x):
	t = 1
	for layer in range(KE_LAYERS):
		t = t * KE_Sign(KE_Dot(w[layer], x[layer]))
	return t

def KE_Load(msg):
	msg = msg.decode()
	return json.loads(msg)["payload"]

def KE_Dump(data):
	return bytearray(json.dumps({"payload":data}), 'utf-8')

def KE_BuildKey(data):
	h = ''
	for n in data:
		for i in n:
			h += str(i)
	print('\n'+h+'\n')
	s = sha256(h.encode('utf-8'))
	return int(s.hexdigest(), 16)

	
class KE_Server(object):
	'''
	Listen for connection. When A TCP is requested send an unencrypted
	request to begin a key exchange. If the client agrees the connection is 
	continued and the pair compute a private key. Once a private key is found,
	all following data will be encrypted using AES-128.
	'''
	def __init__(self, port):
		self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.serversocket.bind(('127.0.0.1', port))
		self.serversocket.listen(1)
		print('Listening on port '+str(port))


	def mainloop(self):
		while 1:
			#Accept connection from client
			(clientsock, address) = self.serversocket.accept()
			ct = KE_ClientThread(clientsock)
			ct.run()
			

class KE_Client(object):
	def __init__(self, port):
		self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.clientsocket.connect(('127.0.0.1', port))
		self.weights = KE_RandSet()
		print("Client rand weights")
		print(self.weights)
 
	def mainloop(self):
		#Send request for KE
		self.clientsocket.send(KE_Dump(KE_CONFIRMATION_CODE))
		print("Initiating Key Exchange")
		#Receive response with confirmation and first set of input vectors
		data = KE_Load(self.clientsocket.recv(KE_BUFF))
		ke = 1 if data == KE_CONFIRMATION_CODE else 0
		while ke:
			# Receive data from server containing input and incstructions
			data = KE_Load(self.clientsocket.recv(KE_BUFF))
			# Instruction from server
			t = data.pop()
			if t == KE_KEY_FOUND:
				print("Possible Key found")
				print("Client weights and key")
				print(self.weights)
				
				key = KE_BuildKey(self.weights)
				print(key)
				if self.keyConfirm(key):
					ke = 0
					print("Key Confirmed")
				else:
					print("Key dropped")
			elif t == KE_ERROR:
				ke = 0
				print('Connection Closed')
			elif t > 1 or t < -1:
				self.clientsocket.send(KE_Dump(KE_ERROR))	
			else:
				# Default case, server sent it's result of training, t
				s = KE_Train(self.weights, data)
				t = t * s
				if t==1:
					self.weights = KE_Learn(self.weights, data, s)
				self.clientsocket.send(KE_Dump(t))
			
		#Use key to encrypt a confirmation message to the server
		#Recieve confirmation
		#Continue communication using AES-128

	def keyConfirm(self, key):
		#Bitwise OR a secret with the derived key
		print("client secret")
		secret = KE_BuildKey(KE_RandSet())
		skey = key ^ secret
		#Send the new key to the server
		self.clientsocket.send(KE_Dump(skey))
		#Recieve a new key that has been OR'ed with the server's secret
		skey = KE_Load(self.clientsocket.recv(KE_BUFF))
		#OR with client secret again and send back to server
		skey = skey ^ secret
		self.clientsocket.send(KE_Dump(skey))
		#Server will reply with 1 if it accept's the key, 0 otherwise
		return KE_Load(self.clientsocket.recv(KE_BUFF))
				

class KE_ClientThread(Thread):
	'''
	A thread object that a server creates to handle a client request.
	'''
	def __init__(self, clientsock):
		self.clientsock = clientsock
		self.weights = KE_RandSet()
		self.syncAt = KE_SYNC
		print("Server rand weights")
		print(self.weights)	
		Thread.__init__(self)

	def run(self):
		ke = self.confirm()
		converged = self.syncAt #Min to sync
		c = 0	#Number of times matched
		while ke:
			x = KE_RandSet() 
			s = KE_Train(self.weights, x)
			p = x[:]
			p.append(s)
			self.clientsock.send(KE_Dump(p))

			t = KE_Load(self.clientsock.recv(KE_BUFF))
			if t > 1 or t<-1:
				#handle KE codes
				pass
			elif t==0:
				ke = 0
				print("Zero t error")
				self.clientsock.send(KE_Dump([KE_ERROR]))
			else:
				# If t is 1 then that means the client's output matched the server's
				if t == 1:
				#Adjust weights accordingly
					self.weights = KE_Learn(self.weights, x, s)
					c = c + 1
					if c == converged:
						self.clientsock.send(KE_Dump([KE_KEY_FOUND]))
						#Build Key
						print("Possible Key found")
						print("server weights and key")
						print(self.weights)
						key = KE_BuildKey(self.weights)
						print(key)
						k = self.keyConfirm(key)
						self.clientsock.send(KE_Dump(k))	
						if k:
							print("Key found")
							ke = 0
						else:
							print("Key dropped")
							c = 0
				else:
					c = 0
				

	def confirm(self):
		data = KE_Load(self.clientsock.recv(KE_BUFF))
		if data == KE_CONFIRMATION_CODE:
			self.clientsock.send(KE_Dump(KE_CONFIRMATION_CODE))
			print("KE Confirmed")
			return 1
		else:
			print("Confirmation Code was not recieved.")
			return 0
	
	def keyConfirm(self, key):
		#Bitwise OR a secret with the recieved key
		print("server secret")
		secret = KE_BuildKey(KE_RandSet())
		skey = KE_Load(self.clientsock.recv(KE_BUFF))
		skey = skey ^ secret
		#Send the new key to the client
		self.clientsock.send(KE_Dump(skey))
		#Recieve a new key that has been OR'ed again with the client's secret
		skey = KE_Load(self.clientsock.recv(KE_BUFF))
		#OR with client secret again and send back to server
		skey = skey ^ secret
		return 1 if skey == key else 0

	
