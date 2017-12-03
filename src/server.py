from keyexchange import KE_Server
import sys

if __name__ == '__main__':
		server = KE_Server(int(sys.argv[1]))
		server.mainloop()
