from keyexchange import KE_Client
import sys

if __name__ == '__main__':
	client = KE_Client(int(sys.argv[1]))
	client.mainloop()
