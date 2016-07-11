#!/usr/bin/python 
# -*- coding: UTF-8 -*-

from struct import *
from tqdm import tqdm
import time

def watch_ota(bfile):

    blebin_file = open(bfile, 'rb')

    packagePerLen = 18
    upgradeList = []
    total_index = 0
    checksum = 0
 
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
                    count += 1
                
                while count < packagePerLen:
                    package += "%02X" % 0
                    count += 1

                upgradeList.append(package)
                total_index += 1

            else:
                break
        blebin_file.close()
        return upgradeList, total_index, checksum
    else:
        return None, 0, 0

if __name__ == "__main__":

    list, total_index, checksum = watch_ota("./1.bin")
    if list != None:
        for i in tqdm(range(0, total_index)):
            print list[i]
            time.sleep(0.001)

    #print list
    print "total_index {0} checksum {1}".format(total_index, checksum)
