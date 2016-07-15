#!/usr/bin/python 
# -*- coding: UTF-8 -*-

from struct import *
import time

def watch_ota(indextype, bfile):

    fileSzie = 0
    packagePerLen = 18
    upgradeList = []
    total_index = 0
    checksum = 0

    blebin_file = open(bfile, 'rb')

    # set file size
    blebin_file.seek(0, 2)
    fileSzie = blebin_file.tell()
    readSize = fileSzie / 2

    # set fw type
    if indextype == 1:
        blebin_file.seek(0, 0)
    else:
        blebin_file.seek(readSize, 0)

    if blebin_file:
        while 1:
            bindata = blebin_file.read(packagePerLen)

            if bindata:
                count = 0
                # index 16byte
                package = "%02X" % (total_index % 256)
                package += "%02X" % (total_index / 256)

                for i in bindata:
                    byte = unpack('B', i)
                    package += "%02X" % byte[0]
		    checksum ^= byte[0]
                    count += 1
                
                while count < packagePerLen:
                    package += "%02X" % 0xFF
		    checksum ^= 0xFF
                    count += 1

                upgradeList.append(package)
                total_index += 1

                if readSize <= total_index * packagePerLen:
                    break

            else:
                break 

        blebin_file.close()
        return upgradeList, total_index, checksum

    else:
        return None, 0, 0

if __name__ == "__main__":

    list, total_index, checksum = watch_ota(2, "./1.bin")
    if list != None:
        for i in list:

            print i
        print "total_index {0} checksum {1}".format(total_index, checksum)

	val = "220D020e02%04X%04X%02X00" % (1, 2, 255) 
	print val
