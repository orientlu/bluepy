#!/usr/bin/python

from __future__ import print_function
import sys
import time
import binascii
import threading
import signal
import btle
import watchOTA

state = "[x]"
ble_conn = None
sub_thread = None
ble_mac = None
last_argv = None
do_exit = False

ota_start_ack = False
ota_send_index = 0
ota_old_version = 0
ota_old_typeIndex = 1


def rprint(*log):
    print(state, "--->", "".join(log))

class MyDelegate(btle.DefaultDelegate):

    def __init__(self, conn):
        btle.DefaultDelegate.__init__(self)
        self.conn = conn

    def handleNotification(self, cHandle, data):
        data = binascii.b2a_hex(data)
        rprint("Notification:", str(cHandle), " data ", data)
        msg_len = int(data[2:4], 16)
        msg_type = int(data[6:8], 16)
        msg_sub_type = int(data[8:10], 16)

        # OTA
        if msg_type == 0x1E:
            if msg_sub_type == 0X01:
                print("Get watch version 0x%08X FW TypeIndex 0x%08X" % (int(data[10:18], 16), int(data[18:26], 16)))

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

                elif self.op == "sendloop":

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

                   
                    while self.op == "sendloop":

                        self.conn.writeCharacteristicRaw(handle, val, True)
                        send_count += 1
                        rprint("Send  msg count %d" % send_count)

                        if wait_ack == 1:
                            if self.conn.waitForNotifications(6.0):
                                recevice_count += 1
                                rprint("recevice msg count %d" % recevice_count)
                            else:
                                timeout_count += 1
                                rprint("Msg Timeout count %d" % timeout_count)
                        time.sleep(delay) 
                else:
                    self.conn.waitForNotifications(0.1)

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
    global ota_start_ack
    global ota_send_index
    global ota_old_version
    global ota_old_typeIndex 

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
    #try:
    if op == 's':
        scanner = btle.Scanner().withDelegate(MyDelegate(None))
        
        timeout = 10.0
        if len(argv) >= 2:
            timeout = int(argv[1])
        devices = scanner.scan(timeout)

        rprint("---------------------------------------------------------\n------> Device:", ble_mac)
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

                ble_conn.writeCharacteristicRaw(handle, val, True)
                rprint("Send handler 0x%04x data %s" % (handle, val))

                if len(argv) >= 4:
                    if argv[3] == "1":
                        ble_conn.waitForNotifications(2.0)

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

                for i in range(0, send_time):
                    rprint("Send count %d" % i)
                    ble_conn.writeCharacteristicRaw(handle, val, True)
                    time.sleep(delay) 

            elif op == "ts":
                if len(argv) < 3:
                    return True

                sub_thread.op = "sendloop"
                sub_thread.argv = argv 

            elif op == "tss":
                sub_thread.op = None
                sub_thread.argv = None

            elif op == "ota":

                if len(argv) >= 3:
                    binfile = argv[1]
                    binVersion = int(argv[2])
                    binType = 1
                    
                    # get device fw version and type
                    val = "2203020E010F"
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 
                    if not ble_conn.waitForNotifications(10):
                        return True

                    fwlist, totalindex, checksum = watchOTA.watch_ota(binType, binfile)
                    
                    # start ota
                    val = "220D020e02%04X%04X%02X00" % (binVersion, binType, totalindex) 
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 
                    ota_start_ack = False
                    if not ble_conn.waitForNotifications(10):
                        return True
                   
                    if ota_start_ack != True:
                        return True
                    
                    # send fw packages
                    ota_send_index = 0
                    while ota_send_index < totalindex:
                        fw = fwlist[ota_send_index]
                        ble_conn.writeCharacteristicRaw(0x23, fw, True) 
                        if ble_conn.waitForNotifications(0.05):
                            print("What happen??")

                        ota_send_index += 1

                        sys.stdout.write('   \r')
                        sys.stdout.flush()
                        sys.stdout.write('{}%\r'.format(ota_send_index*100/totalindex))
                        sys.stdout.flush()
                        
                    # send ota end
                    val = "2203020E04%02X00" % (checksum) 
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 

            else:
                print("command error")

    #except:
    #    pass

    return True


def usage_help():
    print("""   ********************************************************************
        s [time] [mac]                                  : Adv scan 
        c [mac]                                         : Connect
        d                                               : disconnect
        pc                                              : Show primary and characeristic
        l [handle]                                      : Listening -- l 0023
        log                                             : Special op 1
        w [handle] [data] [ack]                         : Write data to characeristic with handle 
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
    global ble_conn
    global sub_thread 
    # test
    ble_mac = "22:02:04:04:01:03"
    ble_connect(ble_mac)

   # open device uart log
    snd_content_str = """\x33\x31"""
    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
    rprint("Test : listenning and open log")

   # listenning
    handle = 0x23
    snd_content_str = """\x01\x00"""
    ble_conn.writeCharacteristic((handle+1), snd_content_str)
   
    #sub_thread.op = "sendloop"
    #sub_thread.argv = {'ts', '23', '2204020B010300', '1', '1'}

    #time.sleep(1)
   # val = "22040201020304"
   # snd_content_str = binascii.a2b_hex(val).decode('utf-8')
   # ble_conn.writeCharacteristic(handle, snd_content_str, True)
   # rprint("Send handler 0x%04x data %s" % (handle, val))

   # ble_disconnect() 



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



