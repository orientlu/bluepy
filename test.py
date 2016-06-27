#!/usr/bin/env python

from bluepy.btle import Scanner, DefaultDelegate

class ScanDelegate(DefaultDelegate):
	def __init__(self):
		DefaultDelegate.__init__(self)

	def handleDiscovery(self, dev, isNewDev, isNewData):
		if isNewDev:
			pass
		elif isNewData:
			print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi)
			print dev.getScanData()

scanner = Scanner().withDelegate(ScanDelegate())
devices = scanner.scan(10.0)

for dev in devices:
	if dev.addr == "16:3e:34:bb:54:82":
		print "Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi)
		for (adtype, desc, value) in dev.getScanData():
			print "  %s = %s" % (desc, value)

