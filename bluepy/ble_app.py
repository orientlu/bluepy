#!/usr/bin/python

from __future__ import print_function
import sys
import time
import binascii
import threading
import signal
import btle

state = "[x]"
ble_conn = None
sub_thread = None
ble_mac = None
last_argv = None
do_exit = False

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
        self.argv = None

    def run(self):
        while not self.exit:
            try:
               
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

                elif self.op == "timesend":

                    argv = self.argv
                    send_count = 0
                    recevice_count = 0
                    timeout_count = 0

                    handle = int(argv[1], 16)
                    val = argv[2]

                    delay = 0 
                    if len(argv) >= 4:
                        delay = float(argv[3])
                    
                    wait_ack = 0
                    if len(argv) >= 5:
                        wait_ack = int(argv[4])

                   
                    while self.op == "timesend":

                        snd_content_str = binascii.a2b_hex(val).decode('utf-8')
                        ble_conn.writeCharacteristic(handle, snd_content_str, True)
                        send_count += 1
                        rprint("Send  msg count %d" % send_count)

                        if wait_ack == 1:
                            if self.conn.waitForNotifications(1.0):
                                recevice_count += 1
                                rprint("recevice msg count %d" % recevice_count)
                            else:
                                timeout_count += 1
                                rprint("Msg Timeout count %d" % timeout_count)
                        time.sleep(delay) 

                else:
                    pass

            except:
                break

        self.conn.disconnect()
        rprint("sub Thread exit");


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
    global last_argv

    if not argv:
        return None
    
    if last_argv and argv[0] == '.':
        argv = last_argv
    else:
        last_argv = argv

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

                if op == 'pc':
                    sub_thread.op = "primary"
                    rprint("DSV")

                elif op == 'l':
                    if len(argv) >= 2:
                        handle = int(argv[1], 16) + 1
                        snd_content_str = """\x01\x00"""
                        ble_conn.writeCharacteristic(handle, snd_content_str)
                        rprint("Set listening 0x%04x" % handle)

                elif op == 'log':
                    snd_content_str = """\x33\x31"""
                    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
                    rprint("Special send 1 : log")

                elif op == 'w':
                    handle = 0x0023
                    if len(argv) >= 2:
                        handle = int(argv[1], 16)
                    
                    val = "22040201020304"
                    if len(argv) >= 3:
                        val = argv[2]
 
                    snd_content_str = binascii.a2b_hex(val).decode('utf-8')
                    ble_conn.writeCharacteristic(handle, snd_content_str, True)
                    rprint("Send handler 0x%04x data %s" % (handle, val))

                elif op == 'wc':
                    handle = 0x0023
                    if len(argv) >= 2:
                        handle = int(argv[1], 16)
                    
                    val = "22040201020304"
                    if len(argv) >= 3:
                        val = argv[2]
                    
                    send_time = 1
                    if len(argv) >= 4:
                        send_time = int(argv[3], 10)
                    
                    delay = 0 
                    if len(argv) >= 5:
                        delay = float(argv[4])

                    snd_content_str = binascii.a2b_hex(val).decode('utf-8')
                    for i in range(0, send_time):
                        rprint("Send count %d" % i)
                        ble_conn.writeCharacteristic(handle, snd_content_str, True)
                        time.sleep(delay) 

                elif op == "ts":
                    if len(argv) < 3:
                        return True

                    sub_thread.op = "timesend"
                    sub_thread.argv = argv 

                elif op == "tss":
                    sub_thread.op = None
                    sub_thread.argv = None 

                else:
                    print("command error")
    except:
        pass

    return True


def usage_help():
    print("""   ********************************************************************
        s [time] [mac]                                  : Adv scan 
        c [mac]                                         : Connect
        d                                               : disconnect
        pc                                              : Show primary and characeristic
        l [handle]                                      : Listening -- l 0023
        log                                             : Special op 1
        w [handle] [data]                               : Write data to characeristic with handle 
        wc [handle] [data] [count] [delay]              : Write data with set count  
        ts [handle] [data] [delay] [ack]                : Test, send data loop  
        tss                                             : stop tc  
        .                                               : Repeat
        q                                               : Quit
    *************************************************************************************************************
          """)


def signal_handler(signal, frame):
    global do_exit
    try:
        do_exit = True
        ble_disconnect()
    except:
        pass


def test():
    global ble_mac
    # test
    ble_mac = "76:66:44:33:22:72"
    ble_connect(ble_mac)

    # listenning
    handler = 0x24
    snd_content_str = """\x01\x00"""
    ble_conn.writeCharacteristic(handler, snd_content_str)

    # open device uart log
    snd_content_str = """\x33\x31"""
    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
    rprint("Test : listenning and open log")



if __name__ == '__main__':
    
    rprint("Application Startt\n")
 
    #btle.Debugging = True
    test()


    signal.signal(signal.SIGINT, signal_handler)

    while True and (not do_exit):
        cmd = raw_input("%s cmd $ " % state)
        argv = cmd.split()
        if process_cmd(argv) == False:
            break


    rprint("Application quit\n")



