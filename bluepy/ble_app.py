#!/usr/bin/python

from __future__ import print_function
import sys
import time
import binascii
import threading
import signal
import traceback
import btle
import watchOTA
import os

state = "[x]"
ble_conn = None
sub_thread = None
ble_mac = None
last_argv = None
do_exit = False

ota_ack_num = 0
ota_pause = False
ota_send_index = 0
ota_old_version = 0
ota_old_typeIndex = 1

no_notification = False

resend_lock = threading.Lock()

def rprint(*log):
    print(state, "--->", "".join(log))

class MyDelegate(btle.DefaultDelegate):

    def __init__(self, conn):
        btle.DefaultDelegate.__init__(self)
        self.conn = conn

    def handleNotification(self, cHandle, data):

        global ota_send_index
        global ota_ack_num
        global ota_old_version
        global ota_old_typeIndex 
        global ota_pause
        global resend_lock
        data = binascii.b2a_hex(data)
        rprint("Notification:", str(cHandle), " data ", data)
        msg_type = int(data[6:8], 16)
        msg_sub_type = int(data[8:10], 16)

        # OTA
        if msg_type == 0x1E:
            if msg_sub_type == 0X01:
                # fw version and type
                strVer = data[16:18] + data[14:16] + data[12:14] + data[10:12]
                strInd = data[24:26] + data[22:24] + data[20:22] + data[18:20]
                ota_old_version = int(strVer, 16)
                ota_old_typeIndex = int(strInd, 16)
                ota_ack_num = 0
                rprint("Get watch version 0x%08X FW TypeIndex 0x%08X" %(ota_old_version, ota_old_typeIndex))

            elif msg_sub_type == 0x02:
                # ota start ack
                ota_ack_num = int(data[10:12], 16)

            elif msg_sub_type == 0x03:
                # resend req
                strdata = data[12:14] + data[10:12]
                resend_lock.acquire()
                ota_send_index = int(strdata, 16)
                resend_lock.release()
                rprint("Ota resend from index %d" % ota_send_index)

            elif msg_sub_type == 0x04:
                # ota end ack
                ota_ack_num = int(data[10:12], 16)

            elif msg_sub_type == 0x05:
                # ota erro
                code = int(data[12:14], 16)
                if code == 0x02:
                    rprint("OTA pause")
                    ota_pause = True

            elif msg_sub_type == 0x06:
                # restart ota
                strdata = data[12:14] + data[10:12]
                ota_send_index = int(strdata, 16)
                ota_pause = False
                rprint("OTA restart %04X" % ota_send_index)

            else:
                pass
        else:
            pass

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            pass
        elif isNewData:
            pass
            rprint("\nDiscovery:", "MAC:", dev.addr, " Rssi ", str(dev.rssi))
  
  #     for (adtype, desc, value) in dev.getScanData():
		#rprint ("  %s(0x%02x) = %s" % (desc, int(adtype), value))


class async_thread(threading.Thread):

    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn
        self.exit = False
        self.op = None
        self.argv = None

    def run(self):
        global no_notification
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
                    if not no_notification:
                        self.conn.waitForNotifications(0.001)

            except:
                #traceback.print_exc()
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

    global ota_send_index
    global ota_ack_num
    global ota_old_version
    global ota_old_typeIndex 
    global ota_pause
    global no_notification
    global resend_lock

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
                    no_notification = True
                    # get device fw version and type
                    val = "2203020E010F"
                    ota_ack_num = 0xFF 
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 
                    
                    wait_timeout = 0
                    while wait_timeout < 10 and ota_ack_num == 0xFF:
                        ble_conn.waitForNotifications(1) 
                        wait_timeout += 1

                    if ota_ack_num != 0:
                        rprint("Failure 2 : didn't get device Version and fw TypeIndex !!")
                        return True

                    if len(argv) >= 2:
                        binVersion = int(argv[1]) 
                        if len(argv) >= 3:
                            binfile = argv[2]
                        else:
                            if os.path.exists("./ota.img"):
                                binfile = "./ota.img"
                            else:
                                rprint("Please give ota.img")
                                return True

                        # judge version
                        if ota_old_version == binVersion:
                            rprint("Failure 3 : same version no need update!!")
                            return True

                        # set new fw TypeIndex
                        if ota_old_typeIndex == 0:
                            binType = 1
                        elif ota_old_typeIndex == 1:
                            binType = 0
                        else:
                            rprint("Failure 4 : TypeIndex unknow!!")
                            return True

                        rprint("I want to Update connection para...wait 5s")
                        time.sleep(5)
                        snd_content_str = """\x33\x10"""
                        ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
                        rprint("Update connection para...wait 3s")
                        time.sleep(3)

                        # get fw image list
                        fwlist, totalindex, checksum = watchOTA.watch_ota(binType, binfile)
                        rprint("New firmware : totalindex %d checksum 0x%02X" %(totalindex, checksum))

                        # send start ota
                        val = "220D020E02"
                        v1 = "%08X" % binVersion
                        v2 = "%08X" % binType
                        v3=  "%04X" % totalindex
                        val = val + v1[6:8] + v1[4:6] + v1[2:4] + v1[0:2]
                        val = val + v2[6:8] + v2[4:6] + v2[2:4] + v2[0:2]
                        val = val + v3[2:4] + v3[0:2]
                        val = val + "00"

                        ota_ack_num = 0xFF
                        ble_conn.writeCharacteristicRaw(0x23, val, True) 
                        wait_timeout = 0
                        while wait_timeout < 10 and ota_ack_num == 0xFF:
                            ble_conn.waitForNotifications(1) 
                            wait_timeout += 1
                       
                        if ota_ack_num != 0:
                            rprint("Failure 6 : OTA start ack not pass!! code %d" % ota_ack_num)
                            return True
                        
                        rprint("Start send firmware packages")

                        # send fw packages
                        ota_send_index = 0
                        ota_pause = False
                        while ota_send_index < totalindex:
                            resend_lock.acquire()
                            fw = fwlist[ota_send_index]
                            ota_send_index += 1
                            resend_lock.release()
                            ble_conn.writeCharacteristicRaw(0x2b, fw, True) 
                            #ble_conn.waitForNotifications(0.001)

                            sys.stdout.write('   \r')
                            sys.stdout.flush()
                            sys.stdout.write('{}%\r'.format(ota_send_index*100/totalindex))
                            sys.stdout.flush()
                            
                            while ota_pause:
                                time.sleep(1)

                        # send ota end
                        val = "2204020E04%02X00" %(checksum) 
                        ota_ack_num = 0xFF
                        ble_conn.writeCharacteristicRaw(0x23, val, True) 
                        wait_timeout = 0
                        while wait_timeout < 10 and ota_ack_num == 0xFF:
                            ble_conn.waitForNotifications(1) 
                            wait_timeout += 1

                        if ota_ack_num != 0:
                            rprint("Failure : OTA end error code %d!!" % ota_ack_num)
                            return True
                        else:
                            rprint("OTA finish!!")

                        # Restart watch
                        time.sleep(5)
                        val = "2203020E0700"
                        ota_ack_num = 0xFF
                        ble_conn.writeCharacteristicRaw(0x23, val, True) 
                        rprint("Restart....")

                        if not ble_conn.waitForNotifications(10):
                            rprint("Restart Error")
                        ble_disconnect()
                elif op == "test":
                    no_notification = True
                    cmd = "220302FD"
                    #Start
                    val = cmd + "1800"
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 
                    if not ble_conn.waitForNotifications(10):
                        rprint("Test Error 1")
                        return True

                    for i in range(0, 0X1A):
                        time.sleep(1)
                        val = cmd + ("%02X00" % i)
                        if i == 0x08 or i== 0x09:
                            continue

                        ble_conn.writeCharacteristicRaw(0x23, val, True) 
                        if not ble_conn.waitForNotifications(10):
                            rprint("Test Error %d" %i)
                            return True
                        rprint("Test pass %d" %i)
                    rprint("Test Finish")

                else:
                    print("command error")

    except:
        ble_disconnect()

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
        ota version [./ota.img]                         : how to ota
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
        traceback.print_exc()


def test():
    global ble_mac
    global ble_conn
    global sub_thread 
    # test
    #ble_mac = "22:88:88:88:88:78"
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


if __name__ == '__main__':
    
    rprint("Application Startt\n")
 
    #btle.Debugging = True
    test()

    signal.signal(signal.SIGINT, signal_handler)

    while not do_exit:
        cmd = raw_input("%s cmd $ " % state)
        argv = cmd.split()
        if process_cmd(argv) == False:
            break
        no_notification = False

    rprint("Application quit\n")



