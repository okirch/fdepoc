#!/usr/bin/python3
#
# Try to predict PCR values at the point when grub needs to unseal
# the SRK to access the Linux /boot partition
#

grub_cfg = '''set btrfs_relative_path="yes"
search --fs-uuid --set=root dfa8e440-65b8-4500-b215-79397d0a797e
set prefix=($root)/boot/grub2
configfile ($root)/boot/grub2/grub.cfg
'''


def parse_bytestring(s, hashbits = None):
	if hashbits is not None:
		assert(len(s) == hashbits / 4)

	b = bytearray()
	while s:
		octet = int(s[:2], 16)
		b.append(octet)
		s = s[2:]

	return b

def print_bytestring(b, prefix = None, trailer = None):
	if prefix:
		print(f"{prefix}: ", end = '')
	for octet in b:
		print("%02x" % octet, end = '')
	if trailer:
		print(f"        {trailer}", end = '')
	print()


class TPM:
	class PCR:
		INITIAL_PCR_VALUE = "0000000000000000000000000000000000000000000000000000000000000000"

		def __init__(self, index, initial = None):
			if initial is None:
				initial = parse_bytestring(self.INITIAL_PCR_VALUE)

			self.index = index
			self.algo = "sha256"
			self.value = initial

		def hash(self, data):
			import hashlib

			m = hashlib.new(self.algo)
			m.update(data)
			return m.digest()

		def extend(self, hash):
			import hashlib

			m = hashlib.new(self.algo)
			m.update(self.value)
			m.update(hash)
			self.value = m.digest()

		def display(self, desc = None):
			print_bytestring(self.value, prefix = f"PCR{self.index}", trailer = desc)

	def __init__(self):
		self.pcr = []
		for i in range(24):
			self.pcr.append(self.PCR(i))

	def extend(self, pcrIndex, data, desc = None):
		pcr = self.pcr[pcrIndex]
		hash = pcr.hash(data)
		pcr.extend(hash)

		return pcr

class Grub:
	GRUB_STRING_PCR = 8
	GRUB_BINARY_PCR = 9

	def __init__(self, bootP, rootP):
		self.tpm = TPM()

		# This is the EFI partition
		self.boot = bootP

		# This is the /boot partition
		self.root = rootP

	def verify_write(self, data, filename):
		if type(data) == str:
			data = data.encode('utf-8')

		pcr = self.tpm.extend(self.GRUB_BINARY_PCR, data)
		pcr.display(filename)

	def verify_string(self, s):
		data = s.encode('utf-8')

		pcr = self.tpm.extend(self.GRUB_STRING_PCR, data)
		pcr.display(s)

	# grub does not hash lines from grub.cfg as-is, but rather a string representation
	# of what it is about to execute. So, for example,
	#   set btrfs_relative_path="yes"
	# is hashed as
	#   set btrfs_relative_path=yes
	#
	def parse_line(self, line):
		line = line.replace('"', '')
		line = line.replace('$root', grub.root)
		grub.verify_string(line)

grub = Grub('hd0,gpt2', 'hd0,gpt3')
grub.verify_write(grub_cfg, f"({grub.boot})/EFI/BOOT/grub.cfg")

for line in grub_cfg.splitlines():
	grub.parse_line(line)

exit(0)
