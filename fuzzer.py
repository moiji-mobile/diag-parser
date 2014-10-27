#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import pprint
import os
import sys
import random
import subprocess
import struct
import time

print "Fuzzing stuff"

usage = "usage: %prog [options] ORIGFILES"
desc = """Example:
   ./fuzzer.py --random 10 raw_dat*.bin
"""

parser = argparse.ArgumentParser(description=desc)
parser.add_argument("files", metavar="FILES", type=str, nargs='+', help="Original input files")
parser.add_argument("--random", dest="random", type=int, default=1, help="How random is random")
args = parser.parse_args()

pprint.pprint(args)

def unique_fuzz_file(file_name_begin):
    counter = 1
    while 1:
        file_name = file_name_begin + '_' + str(counter) + ".cnf"
        try:
            fd = os.open(file_name, os.O_CREAT | os.O_EXCL)
            os.fdopen(fd).close()
            return file_name
        except OSError:
            pass

        counter += 1

def setlimits():
    #sys.stdout.write("Setting resource limit in child (pid %d): %d s\n" % (os.getpid(), maxTime))
    resource.setrlimit(resource.RLIMIT_CPU, (maxTime, maxTime))

random.seed(time.time())
messages = []

def go_through_file(fname) :
	with open(fname, "rb") as in_file:
		more_in_file = True
		while more_in_file:
			message = []
			for i in xrange(4096) :
				val = in_file.read(1)
				if not val:
					more_in_file = False
					break
				val = ord(val)

				if val == 0x7e :
					message.append(val)
					break

				if val == 0x7d :
					message.append(val)
					val = in_file.read(1)
					if not val:
						more_in_file = False
						break
					val = ord(val)

				message.append(val)

			#print "message is: ", message
			print '%dB' % len(message)
			a = struct.pack('%dB' % len(message), *message)
			messages.append(a)

def remove_random_bytes(data, max_remove) :
	if random.randint(0,100) < 90:
		return data

	to_remove = random.randint(0, max_remove)
	for i in range(to_remove) :
		skip_how_many = random.randint(1,100)
		end = len(data)-skip_how_many
		if end < 0 :
			continue

		from_pos = random.randint(0, end)
		data = data[:from_pos] + data[from_pos+skip_how_many:]

	return data

def perturb_values(data, max_num_perturbed) :
	if len(data) == 0:
		return data

	tmp = struct.unpack("%dB" % len(data), data)
	tmp = list(tmp)
	for x in range(random.randint(0,max_num_perturbed)) :
		assert len(tmp) > 0
		mess_up_at = random.randint(0,len(tmp)-1)
		tmp[mess_up_at] = random.randint(0,255)

	tmp = remove_random_bytes(tmp, 2)

	return struct.pack("%dB" % len(tmp), *tmp)

for fname in args.files:
	go_through_file(fname)


def check_for_uper(data) :
	for line in data:
		if "SEQUENCE_decode_uper".lower() in line.lower():
			return True

	return False

for x in xrange(1000*1000) :

	fuzz_fname = unique_fuzz_file("fuzz_")
	print "Fuzzing attempt", x, " fname:", fuzz_fname
	f = open(fuzz_fname, "wb")
	#for at in range(len(messages)) :
	for a in range(random.randint(1, 100)) :
		at = random.randint(0, len(messages)-1)
		towrite = messages[at]
		towrite = perturb_values(towrite, 1)
		f.write(towrite)
	f.close()

	if random.randint(0,100) > 80:
		os.system("radamsa %s > %s_new" % (fuzz_fname, fuzz_fname))
		os.unlink(fuzz_fname)
		fuzz_fname = fuzz_fname + "_new"
		print "New fuzz name:" , fuzz_fname

	toexec = "valgrind ./diag_import 0 0 ".split()
	f = open(fuzz_fname, "rb")
	p = subprocess.Popen(toexec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin = f)
	out, err = p.communicate()
	f.close()

	out = out.split("\n")
	err = err.split("\n")
	for line in err:
		print line
		line = line.lower()
		if "signal" in line or "fail" in line or "invalid" in line or "abort" in line:
			if "assert" in line:
				continue

			if check_for_uper(err):
				continue

			print "out:", "\n".join(out)
			print "err:", "\n".join(err)
			print "filename:", fuzz_fname
			exit(-1)

	os.unlink(fuzz_fname)

