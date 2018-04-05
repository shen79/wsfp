#!/usr/bin/python

import socket, sys, os, base64, re, glob
from pprint import *

class WSFP:
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.kdb = {}
		self.badrequests = {
			'bad_content-length': 	'POST / HTTP/1.0\nConnection: close\nContent-Length: x\n\n',
			'bad_host': 			'GET / HTTP/1.0\nHost: x]x:-\nConnection: close\n\n',
			'bad_method': 			'GARBLARGH / HTTP/1.0\nConnection: close\n\n',
			'bad_proto': 			'GET / GARBLARGH/1.0\nConnection: close\n\n',
			'bad_proto_version': 	'GET / HTTP/x.y\nConnection: close\n\n',
			'bad_uri': 				'GET x HTTP/1.0\nConnection: close\n\n',
			'options': 				'OPTIONS * HTTP/1.0\nConnection: close\n\n'
		}
		self.results = {}
		self.keys = ['code', 'proto', 'msg', 'error']

#	def load_requests(self):
#		ret = {}
#		for fn in glob.glob('./rq/*.rq'):
#			rname = os.path.basename(fn)[:-3]
#			f = open(fn)
#			fc = ''.join(f.readlines())
#			self.requests[rname] = fc.rstrip() + "\n\n"
#			self.requests[rname].replace("\n", "\r\n")
#			print "%s %s %s | %s" % (ret['proto'], ret['code'], ret['msg'], ret['error'])

	def run(self):
#		self.load_requests()
		self.run_tests()
#		pprint(self.results)
		self.analyze()
#		self.save_kdb()

	def run_tests(self):
		for rqn in self.badrequests:
			self.results[rqn] = self.req(rqn)

	def analyze(self):
		self.load_kdb()
		self.analyze_server_header()
		self.analyze_match()
		# 
		# proxy check
		# CVE check

	def load_kdb(self):
		files = glob.glob('./kdb/*.dat')
		for f in files:
			fh = open(f)
			lines = fh.readlines()
			for line in lines:
				s, v, b64 = line.split(' ', 2)
				sv = "%s %s" % (s, v)
				self.kdb[sv] = eval(base64.b64decode(b64))
				
#				pprint(server)
#				pprint(version)
#				pprint(b64)
		pprint(self.kdb)
				

	def analyze_match(self):
		t_stat, stat = {}, {}
		kdbsize = len(self.kdb)
		for server in self.kdb:
			for rqn in self.kdb[server]:
				for var in self.kdb[server][rqn]:
					obj = "%s.%s=%s" % (rqn, var, self.kdb[server][rqn][var])
					try:
						t_stat[obj] += 1
					except KeyError:
						t_stat[obj] = 1
		for k in t_stat:
			stat[k] = "%.02f" % long(t_stat[k]) / kdbsize
		pprint(stat)



	def save_kdb(self):
		res = {}
		for r in self.results:
			res[r] = self.results[r]
			res[r].pop('headers')
		
		rr = pformat(res).lstrip().split("\n")
		ret = ''
		for l in rr: ret += re.sub(r'^\s+', '', l)
#		print 'Result:', ret
		ret = base64.b64encode(ret)
#		print 'Result:', ret
		a = '-'
		while a not in ['y', 'n']:
			print 'do you know what is it? wanna save?'
			a = sys.stdin.readline().strip()
			if a == 'y':
				print 'server?'
				server = sys.stdin.readline().strip()
				print 'version?'
				version = sys.stdin.readline().strip()
				f = open('./kdb/'+server+'_'+version+'.dat', 'w')
				f.write("%s %s %s" % (server, version, ret))

	def analyze_server_header(self):
		ret = []
		for r in self.results:
			try:
				server = self.results[r]['headers']['server']
			except KeyError as e:
				pass
			else:
				if server not in ret:
					ret.append(server)
		print "Server headers found:\n\t%s" % "\n\t".join(ret)
		for h in ret:
			self.server_version(h)

	def server_version(self, ver):
		ret = {}
		# TODO, this implementation is pretty poor... imean crappy..
		try:
			name, ver = ver.split("/")
		except:
			pass
		else:
			print "Server type: %s\nServer version: %s" % (name, ver)
		
				
	
	def req(self, rqname):
#		print ":: %s" % rqname
		ret = {}
		s = self.conn()
		s.send(self.badrequests[rqname])
		f = s.makefile()
		r = f.readline().strip()
		ret = {
			'proto': 	'',
			'code':		'',
			'msg':		'',
			'error':	'',
			'headers':	{}
		}
#		pprint(r)
		try:
			ret['proto'], ret['code'], ret['msg'] = r.split(' ', 2)
		except ValueError as e:
			ret['error'] = 1 # e
			return ret
			
#		print "0: %s | %s | %s" % (proto, code, msg)
		while 1:
			r = f.readline().strip()
			if r == '':
				break
			hdr, val = r.split(':', 1)
			hdr = hdr.strip().lower()
			val = val.strip()
#			print "1: %s | %s " % (hdr, val)
			if hdr in ret['headers']:
				print 'DUPLICATE HEADER: %s: %s' % (hdr, val)
			ret['headers'][hdr] = val
		s.close()
		return ret
			
			
		
		
		
	
	def conn(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((self.host, self.port))
		except socket.error as e:
			print "err: %s\n" % e
			sys.exit(1)
		return s
		
			





if __name__ == '__main__':
	wfp = WSFP(sys.argv[1], int(sys.argv[2]))
	wfp.run()
