#!/usr/bin/python

from __future__ import print_function
import sys
import time
import binascii
import threading
import signal
import btle

state = "[x]"

def rprint(*log):
    print(state, "--->", "".join(log))

class MyDelegate(btle.DefaultDelegate):
    def __init__(self, conn):
        btle.DefaultDelegate.__init__(self)
        self.conn = conn

    def handleNotification(self, cHandle, data):
        data = binascii.b2a_hex(data)
        rprint("Notification:", str(cHandle), " data ", data)
	
    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            pass
        elif isNewData:
            pass
            rprint("\nDiscovery:", "MAC:", dev.addr, " Rssi ", str(dev.rssi))
	    for (adtype, desc, value) in dev.getScanData():
		rprint ("  %s(0x%02x) = %s" % (desc, int(adtype), value))


class async_thread(threading.Thread):
    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn
        self.exit = False
        self.op = None

    def run(self):

        while not self.exit:
            try:
                #self.conn.waitForNotifications(1.0) 
               
                if self.op == "primary":
                    print("-------------------------------------------------")
                    sers = self.conn.getServices()
                    for ser in sers:
                        print("\n**************************************************\n")
                        print("Services :")
                        print("uuid : %s " % ser.uuid)
                        print(ser)
                        print("\nCharacteristic :")
                        chars = ser.getCharacteristics()
                        for char in chars:
                            print("Value Handler 0x%04x  Des : %s" % (char.getHandle(), char.propertiesToString()))
                            print("UUID %s" % char.uuid)
                            print("    {}, hnd={}, supports {}".format(char, hex(char.handle), char.propertiesToString()))
                            if (char.supportsRead()):
                                try:
                                    print("    ->", repr(char.read()))
                                except:
                                    print("    ->")

                    self.op = None
                    print("-------------------------------------------------")
                else:
                    pass

            except:
                break

        self.conn.disconnect()
        rprint("sub Thread exit");



ble_conn = None
sub_thread = None
ble_mac = None

def ble_connect(devAddr):

    global ble_conn
    global sub_thread 
    global ble_op
    global state

    if not devAddr is None and ble_conn is None:
        ble_conn = btle.Peripheral(devAddr, btle.ADDR_TYPE_PUBLIC)
        ble_conn.setDelegate(MyDelegate(ble_conn))

        sub_thread = async_thread(ble_conn)
        sub_thread.start()
        state = "[c]"
        rprint("connected")


def ble_disconnect():

    global ble_conn
    global sub_thread
    global state
    if not sub_thread is None:
        sub_thread.exit = True
        sub_thread = None
        ble_conn = None
        state = "[x]"
        rprint("disconnected")


def process_cmd(argv):

    global ble_mac 
    global ble_conn
    if not argv:
        return None

    op = argv[0]
    try:
        if op == 's':
            scanner = btle.Scanner().withDelegate(MyDelegate(None))
            
            timeout = 10.0
            if len(argv) >= 2:
                timeout = int(argv[1])
            devices = scanner.scan(timeout)

            rprint("---------------------------------------------------------\n------> Device:")
            if len(argv) >= 3 or ble_mac != None:

                if len(argv) >= 3:
                    ble_mac = argv[2]

                for dev in devices:
                    if dev.addr == ble_mac:
                        print("\nDiscovery:", "MAC:", dev.addr, " Rssi ", str(dev.rssi))

                        for (adtype, desc, value) in dev.getScanData():
                            rprint ("  %s(0x%x) = %s" % (desc, int(adtype), value))

                        break
            rprint("---------------------------------------------------------\n Scan End") 

        elif op == "c":
            if len(argv) >= 2 or ble_mac != None:
                if len(argv) >= 2:
                    ble_mac = argv[1]

                ble_connect(ble_mac)

            else:
                rprint("use : c devAddr")

        elif op == "d":
            ble_disconnect()
        elif op == "q":
            ble_disconnect()
            return False
        elif op == "h":
            usage_help()

        else:
            if ble_conn is None:
                rprint("connect first")
                return None 
            else: 

                if op == 'p':
                    sub_thread.op = "primary"
                    rprint("DSV")

                elif op == 'l':
                    if len(argv) >= 2:
                        handler = int(argv[1], 16) + 1
                        snd_content_str = """\x01\x00"""
                        ble_conn.writeCharacteristic(handler, snd_content_str)
                        rprint("Set listening 0x%04x" % handler)

                elif op == 'log':
                    snd_content_str = """\x33\x31"""
                    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
                    rprint("Special send 1 : log")

                elif op == 'w':
                     
                    handle = 0x0023
                    if len(argv) >= 3:
                        handle = int(argv[1], 16)
                    
                    val = "22040201020304"
                    if len(argv) >= 3:
                        val = argv[2]
 
                    snd_content_str = binascii.a2b_hex(val).decode('utf-8')
                    for i in range(0, 5):
                        rprint("Send count %d" % i)
                        ble_conn.writeCharacteristic(handle, snd_content_str, True)

                else:
                    print("command error")
    except:
        pass

    return True

def usage_help():
    print("""   ********************************************************************
        s [time] [mac]      : adv scan 
        c [mac]             : connect
        d                   : disconnect
        p                   : show primary and characeristic
        l [handle]          : listening -- l 0023
        log                 : Special op 1
        w [handle] [data]   : write data to characeristic with handle   
        q                   : quit
    *************************************************************************************************************
          """)

do_exit = False
def signal_handler(signal, frame):
    global do_exit
    try:
        do_exit = True
    except:
        pass

if __name__ == '__main__':

    btle.Debugging = True

    ble_mac = "76:66:44:33:22:72"
    ble_connect(ble_mac)

    while True:
        cmd = raw_input()
        argv = cmd.split()
        if process_cmd(argv) == False:
            break

   # signal.signal(signal.SIGINT, signal_handler)

