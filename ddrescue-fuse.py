#!/usr/bin/python3
import argparse
import errno
import fcntl
import io
import llfuse
import logging
import os
import queue
import shlex
import signal
import stat
import struct
import subprocess
import sys
import threading

ddrescue_pollution = 5

def get_device_size(dev):
	# NOTE: not ideal, as it may cause the OS to try buffering stuff
	with open(dev, 'rb') as f:
		return f.seek(0, io.SEEK_END)
	
	#dev_stat = os.stat(dev)
	#return dev_stat.st_size
	
	#OP_BLKGETSIZE64 = 0x40081272  # system-specific! FIXME
	#fd = os.open(dev, os.O_RDONLY | os.O_PATH)
	#buf = fcntl.fcntl(fd, OP_BLKGETSIZE64, b' ' * 8)
	#os.close(fd)
	#return struct.unpack('L', buf)[0]

class DDRescueProcess:
	def __init__(self, options):
		self.logger = logging.getLogger('DDRescueProcess')
		self.base_argv = ('ddrescue', options.source, options.image, options.mapfile, *shlex.split(options.ddrescue_options))
		self.timeout_recovery = options.timeout_recovery
		self.do_background()
	
	def __del__(self):
		self.stop_activity()
	
	def start_activity(self, extra_argv):
		self.child = subprocess.Popen(self.base_argv + extra_argv)
	
	def stop_activity(self):
		if not hasattr(self, 'child'): return
		self.logger.info('Interrupting ddrescue')
		self.child.send_signal(signal.SIGINT)
		self.child.wait()
		assert self.child.returncode in (0, -signal.SIGINT)
		print('\n' * ddrescue_pollution)
	
	def do_background(self):
		self.logger.info('Starting background ddrescue')
		self.start_activity( ('-r', '-1',) )
	
	def recover_bytes(self, pos, size):
		self.stop_activity()
		if self.timeout_recovery:
			req_timeout = (size + 511) // 512 * self.timeout_recovery
			req_timeout += 1  # time to read/write mapfile
		else:
			req_timeout = None
		self.logger.info('Starting ddrescue with domain 0x%x-0x%x (timeout after %s seconds)' % (pos, pos + size - 1, req_timeout))
		self.start_activity( ('-r', '-1', '--input-position', str(pos), '--size', str(size)) )
		
		my_queue = queue.PriorityQueue()
		
		def child_completed():
			self.child.wait()
			my_queue.put(0)
		waiter = threading.Thread(target=child_completed)
		waiter.start()
		
		if self.timeout_recovery:
			def timeout_occurred():
				my_queue.put(2)
			timer = threading.Timer(req_timeout, timeout_occurred)
			timer.start()
		
		e = my_queue.get()
		if e == 0:  # completed
			if self.timeout_recovery: timer.cancel()
			assert not self.child.returncode
			print('\n' * ddrescue_pollution)
		elif e == 2:  # timeout
			self.logger.info('Recovery timed out')
			self.stop_activity()
		
		self.do_background()

class DDRescueFS(llfuse.Operations):
	def __init__(self, options):
		super(DDRescueFS, self).__init__()
		self.logger = logging.getLogger('DDRescueFS')
		self.options = options
		self.image = options.image
		self.mapfile = options.mapfile
		self.size = get_device_size(options.source)
		self.filename = b'image'
		self.inode = llfuse.ROOT_INODE + 1
		self.process = DDRescueProcess(options)
		self.done_cache = {}
	
	def getattr(self, inode, ctx=None):
		entry = llfuse.EntryAttributes()
		if inode == llfuse.ROOT_INODE:
			entry.st_mode = (stat.S_IFDIR | 0o755)
			entry.st_size = 0
		elif inode == self.inode:
			entry.st_mode = (stat.S_IFREG | 0o444)
			entry.st_size = self.size
		else:
			raise llfuse.FUSEError(errno.ENOENT)
		
		image_stat = os.stat(self.image)
		entry.st_atime_ns = image_stat.st_atime_ns
		entry.st_mtime_ns = image_stat.st_mtime_ns
		entry.st_ctime_ns = image_stat.st_ctime_ns
		
		# TODO: limit entry.st_blksize by device blksize too?
		entry.st_blksize = image_stat.st_blksize
		entry.st_blocks = image_stat.st_blocks
		
		entry.st_gid = os.getgid()
		entry.st_uid = os.getuid()
		entry.st_ino = inode
		entry.generation = 1
		
		# FIXME: check permissions of image+mapfile and limit st_mode?
		entry.st_nlink = 1
		
		entry.attr_timeout = 0
		entry.entry_timeout = 2**31
		
		return entry
	
	def lookup(self, parent_inode, name, ctx=None):
		if parent_inode != llfuse.ROOT_INODE or name != self.filename:
			raise llfuse.FUSEError(errno.ENOENT)
		return self.getattr(self.inode)
	
	def opendir(self, inode, ctx=None):
		if inode != llfuse.ROOT_INODE:
			raise llfuse.FUSEError(errno.ENOENT)
		return inode
	
	def readdir(self, fh, off):
		assert fh == llfuse.ROOT_INODE
		
		# only one entry
		if off == 0:
			yield (self.filename, self.getattr(self.inode), 1)
	
	def open(self, inode, flags, ctx=None):
		if inode != self.inode:
			raise llfuse.FUSEError(errno.ENOENT)
		if flags & os.O_RDWR or flags & os.O_WRONLY:
			raise llfuse.FUSEError(errno.EPERM)
		return inode
	
	def read_mapfile(self, pos, size):
		self.logger.debug('Looking for 0x%x-0x%x (%u bytes)' % (pos, pos + size - 1, size))
		
		for (c_pos, c_size) in self.done_cache.items():
			if c_pos > pos: continue
			if c_pos + c_size - 1 < pos: continue
			if c_pos + c_size < pos + size: continue
			return True
		
		current_pos = None
		# NOTE: quietly assumes no overlapping regions in mapfile
		found = 0
		with open(self.mapfile, 'r') as f:
			while True:
				line = f.readline()
				comment_pos = line.find('#')
				if comment_pos > -1:
					line = line[:comment_pos]
				if line == '': continue
				line = line.split()
				if current_pos is None:
					assert len(line) == 2
					current_pos = line[0]
					continue
				assert len(line) == 3
				assert line[0][:2] == '0x'
				map_pos = int(line[0], 0x10)
				assert line[1][:2] == '0x'
				map_size = int(line[1], 0x10)
				map_status = line[2]
				if map_status == '+':
					# cache it
					self.done_cache[map_pos] = map_size
				if map_pos + map_size - 1 < pos:
					continue
				if map_pos >= pos + size:
					assert False # gap?
				if map_status != '+':
					self.logger.debug('Incomplete in map %s' % (line,))
					return False
				map_ignored_leading = pos - map_pos
				if map_pos + map_size > pos + size:
					map_ignored_trailing = (map_pos + map_size) - (pos + size)
				else:
					map_ignored_trailing = 0
				map_found = map_size - map_ignored_leading - map_ignored_trailing
				found += map_found
				self.logger.debug('Got %u bytes in map %s (total %u found)' % (map_found, line, found))
				if found == size:
					break
		return True
	
	def get_bytes(self, pos, size):
		have_data = self.read_mapfile(pos, size)
		if not have_data:
			self.process.recover_bytes(pos, size)
			if not self.read_mapfile(pos, size):
				raise llfuse.FUSEError(errno.EIO)
		
		with open(self.image, 'rb') as f:
			assert pos == f.seek(pos, io.SEEK_SET)
			data = f.read(size)
		assert len(data) == size
		return data
	
	def read(self, fh, off, size):
		assert fh == self.inode
		if off + size > self.size:
			size = self.size - off
		if size == 0:
			return b''
		return self.get_bytes(off, size)

def parse_args():
	parser = argparse.ArgumentParser()
	
	parser.add_argument('mountpoint', help='Where to mount the file system')
	parser.add_argument('--source', help='Source device', required=True)
	parser.add_argument('--image', help='Image file', required=True)
	parser.add_argument('--mapfile', help='Map file', required=True)
	parser.add_argument('--ddrescue-options', help='Additional options for ddrescue', default='')
	parser.add_argument('--debug', action='store_true', default=False, help='Enable debugging output')
	parser.add_argument('--debug-fuse', action='store_true', default=False, help='Enable FUSE debugging output')
	parser.add_argument('--timeout-recovery', type=int, default=None, help='Give up recovery after N seconds per 512 bytes')
	
	return parser.parse_args()

def main():
	options = parse_args()
	sys.stderr.write('\n' * ddrescue_pollution)
	sys.stderr.flush()
	term_up = '\x1B[A'
	clear_to_eol = '\x1B[K'
	logging.basicConfig(format='\r' + (term_up * ddrescue_pollution) + '%(asctime)-23s %(levelname)-7s %(name)s: %(message)s' + clear_to_eol + ('\n' * ddrescue_pollution))
	if options.debug:
		logging.getLogger().setLevel(logging.DEBUG)
		logging.getLogger().debug('Debug logging enabled')
	else:
		logging.getLogger().setLevel(logging.INFO)
	
	fs = DDRescueFS(options)
	fuse_options = set(llfuse.default_options)
	fuse_options.add('fsname=ddrescuefs')
	if options.debug_fuse:
		fuse_options.add('debug')
	
	llfuse.init(fs, options.mountpoint, fuse_options)
	try:
		llfuse.main(workers=1)
	except:
		llfuse.close(unmount=False)
		raise
	
	llfuse.close()

if __name__ == '__main__':
	main()
