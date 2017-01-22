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
import xlwt

import struct

excel_name=time.strftime('%Y-%m-%d_%H:%M:%S',time.localtime(time.time()))+".xls"
excel_file=xlwt.Workbook()
excel_table=excel_file.add_sheet("1")
excel_index=0


import wx
from matplotlib.figure import Figure
import matplotlib.font_manager as font_manager
from matplotlib.backends.backend_wxagg import FigureCanvasWxAgg as FigureCanvas
import numpy as np

x_data = [None] * 300
y_data = [None] * 300
z_data = [None] * 300


state = "[x]"
ble_conn = None
sub_thread = None
ble_mac = None
last_argv = None
do_exit = False

ota_ack_num = 0
ota_pause = False
ota_send_index = 0
ota_old_version = "303030303031"
ota_old_typeIndex = 1
ota_end_ack = 0xff

no_notification = False

resend_lock = threading.Lock()

def rprint(*log):
    print(state, "--->", "".join(log))

class MyDelegate(btle.DefaultDelegate):

    count = 0
    def __init__(self, conn):
        btle.DefaultDelegate.__init__(self)
        self.conn = conn

    def handleNotification(self, cHandle, data):

        global ota_send_index
        global ota_ack_num
        global ota_end_ack
        global ota_old_version
        global ota_old_typeIndex
        global ota_pause
        global resend_lock

        if cHandle == 0x2B:
                head = struct.unpack("B", data[0])[0]
                print("Head %02x len %d"% (head, len(data)))
                s_len = len(data)
                if s_len % 2 == 0:
                    s_len = 0

                index = 1
                global excel_table
                global excel_name
                global excel_file
                global excel_index

                global x_data
                global y_data
                global z_data
                while index < s_len:
                    point=struct.unpack('<hhh', data[index:index+6])
                    index += 6
                    excel_table.write(excel_index, 0, str(point[0]))
                    excel_table.write(excel_index, 1, str(point[1]))
                    excel_table.write(excel_index, 2, str(point[2]))
                    excel_index += 1
                    x_data = x_data[1:] + [(point[0])]
                    y_data = y_data[1:] + [(point[1])]
                    z_data = z_data[1:] + [(point[2])]
                    print("(%d %d %d)"%(point[0], point[1], point[2]))
                excel_file.save(excel_name)
                data = binascii.b2a_hex(data)
                print("Notification: ", data)
        else :
                data = binascii.b2a_hex(data)

                self.count += 1
                rprint("Notification:", str(cHandle), " pata ", data)
                rprint("Rx index : %d" %self.count)

                msg_type = int(data[6:8], 16)
                msg_sub_type = int(data[8:10], 16)

                # OTA
                if msg_type == 0x1E:
                    if msg_sub_type == 0X01:
                        # fw version and type
                        ota_old_version = data[10:22]
                        ota_old_typeIndex = int(data[22:24], 16)
                        ota_ack_num = 0
                        rprint("Get watch version V.%s FW TypeIndex 0x%02X" %(ota_old_version, ota_old_typeIndex))

                    elif msg_sub_type == 0x02:
                        # ota start ack
                        ota_ack_num = int(data[10:12], 16)

                    elif msg_sub_type == 0x03:
                        # resend req
                        strdata = data[12:14] + data[10:12]
                        resend_lock.acquire()
                        ota_send_index = int(strdata, 16)
                        resend_lock.release()
                        rprint("Ota resend from index 0x%04X" % ota_send_index)

                    elif msg_sub_type == 0x04:
                        # ota end ack
                        ota_end_ack = int(data[10:12], 16)

                    elif msg_sub_type == 0x05:
                        # ota erro
                        code = int(data[12:14], 15)
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
                # authorization
                elif msg_type == 0x21:
                    if msg_sub_type == 0X02:
                        before_vbat = int((data[12:14] + data[10:12]), 16)
                        after_vbat = int((data[16:18] + data[14:16]), 16)
                        rprint("Battery : before : %d after : %d"% (before_vbat, after_vbat))

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

            except btle.BTLEException:
                traceback.print_exc()
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
        time.sleep(1)
        ble_conn.disconnect()
        ble_conn = None
        state = "[x]"
        rprint("disconnected")


def process_cmd(argv):
    global ble_mac 
    global ble_conn
    global last_argv

    global ota_send_index
    global ota_end_ack
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
                        rprint("Failure 1 : didn't get device Version and fw TypeIndex !!")
                        return True

                    binVersion = "393939393939"
                    if os.path.exists("./ota.img"):
                        binfile = "./ota.img"
                    else:
                        rprint("Please give ota.img")
                        return True

                    # judge version
                    if ota_old_version == binVersion:
                        rprint("Failure 2 : same version no need update!!")
                        return True

                    # set new fw TypeIndex
                    if ota_old_typeIndex == 0:
                        binType = 1
                    elif ota_old_typeIndex == 1:
                        binType = 0
                    else:
                        rprint("Failure 3 : TypeIndex unknow!!")
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
                    v1 = "%02X" % binType
                    v2=  "%04X" % totalindex
                    v3 = "%02X" % checksum
                    val = val + binVersion
                    val = val + v1
                    val = val + v2[2:4] + v2[0:2]
                    val = val + v3 
                    val = val + "00"

                    ota_ack_num = 0xFF
                    ble_conn.writeCharacteristicRaw(0x23, val, True) 
                    wait_timeout = 0
                    while wait_timeout < 10 and ota_ack_num == 0xFF:
                        if not ble_conn.waitForNotifications(1): 
                            ble_conn.writeCharacteristicRaw(0x23, val, True) 

                        wait_timeout += 1
                   
                    if ota_ack_num != 0:
                        rprint("Failure 5 : OTA start ack not pass!! code %d" % ota_ack_num)
                        return True
                    
                    rprint("Start send firmware packages")

                    # send fw packages
                    ota_send_index = 0
                    ota_pause = False

                    start_time = time.time()
                    ota_end_ack = 0xff
                    while ota_send_index < totalindex:

                        try :

                            resend_lock.acquire()
                            i = 0
                            if len(argv) >= 2:
                                fw = ""
                            else:
                                fw = "B0"

                            while ota_send_index < totalindex and i < 10:

                                fw += fwlist[ota_send_index]
                                ota_send_index += 1
                                i += 1

                            rprint("IMG %s" % (fw))
                            resend_lock.release()

                            ble_conn.writeCharacteristicRaw(0x2b, fw, True) 

                            if ble_conn.waitForNotifications(0.001):
                                no_notification = False
                                time.sleep(0.07)
                                no_notification = True

                            sys.stdout.write('   \r')
                            sys.stdout.flush()
                            sys.stdout.write('{}%\r'.format(ota_send_index*100/totalindex))
                            sys.stdout.flush()
                            
                            while ota_pause:
                                time.sleep(1)

	                except btle.BTLEException:

                            rprint("****************** disconnect reconnecting!!!")

                            ble_disconnect()
                            ble_connect(ble_mac)
                           # listenning

                            snd_content_str = """\x01\x00"""
                            handle = 0x23
                            ble_conn.writeCharacteristic((handle+1), snd_content_str)

                            handle = 0x27
                            ble_conn.writeCharacteristic((handle+1), snd_content_str)

                            handle = 0x2b;
                            ble_conn.writeCharacteristic((handle+1), snd_content_str)


                            time.sleep(5)
                            snd_content_str = """\x33\x10"""
                            ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
                            time.sleep(3)

                    # ota end
                    rprint("Total_time : %d" % (time.time() - start_time))
                    rprint("Total_packages : %d" % (totalindex))

                    wait_timeout = 0
                    while wait_timeout < 10 and ota_end_ack == 0xFF:
                        ble_conn.waitForNotifications(1) 
                        wait_timeout += 1

                    if ota_end_ack != 0:
                        rprint("Failure : OTA end error code %d!!" % ota_end_ack)
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
                        if not ble_conn.waitForNotifications(5):
                            rprint("Test Error %d" %i)
                            return True
                        rprint("Test pass %d" %i)
                    rprint("Test Finish")

                elif op == "stream":

                    no_notification = True


                    time.sleep(0.5)

                    handle = 0x2b;
                    snd_content_str = """\x33\x10"""
                    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)
                    rprint("Update connection para...wait 3s")

                    time.sleep(3)

                    snd_content_str = "C0"
                    snd_content_str += "55" * 15 * 10
                    snd_count  = 10
                    i = snd_count
                    start_time = time.time()
                    timeout = 0
                    while i > 0:
                        ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
                        rprint("Send index : %d" %(snd_count - i))
                        i -= 1
                        #time.sleep(0.1)
                        if not ble_conn.waitForNotifications(5):
                            rprint("Time out -------")

                    rprint("Total_time : %d" % (time.time() - start_time))
                else:
                    print("command error")

    except btle.BTLEException:
        traceback.print_exc()
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
        ota [11]                                        : ota [old ota]
        .                                               : Repeat
        q                                               : Quit
    *************************************************************************************************************
          """)


def signal_handler(signal, frame):
    global do_exit
    try:
        do_exit = True
        ble_disconnect()
    except btle.BTLEException:
        traceback.print_exc()

# wxWidgets object ID for the timer  
TIMER_ID = wx.NewId()
# number of data points  
POINTS = 300

class PlotFigure(wx.Frame):
    """Matplotlib wxFrame with animation effect"""
    def __init__(self):
        wx.Frame.__init__(self, None, wx.ID_ANY, title="show acc lllll", size=(1000, 600))
        # Matplotlib Figure  
        self.fig = Figure((10, 6), 100)
        # bind the Figure to the backend specific canvas  
        self.canvas = FigureCanvas(self, wx.ID_ANY, self.fig)
        # add a subplot  
        self.ax = self.fig.add_subplot(111)

        # limit the X and Y axes dimensions  
        self.ax.set_ylim([-600, 700])
        self.ax.set_xlim([0, POINTS])

        self.ax.set_autoscale_on(False)

        self.ax.set_xticks([])
        # we want a tick every 10 point on Y (101 is to have 10  
        self.ax.set_yticks(range(-600, 700, 100))
        # disable autoscale, since we don't want the Axes to ad  
        # draw a grid (it will be only for Y)  
        self.ax.grid(True)
        # generates first "empty" plots  
        self.user = [None] * POINTS
        self.user_1 = [None] * POINTS
        self.user_2 = [None] * POINTS
        self.l_user,=self.ax.plot(range(POINTS),self.user,label='x%')
        self.l_user_1,=self.ax.plot(range(POINTS),self.user_1,label='y%')
        self.l_user_2,=self.ax.plot(range(POINTS),self.user_2,label='z%')

        # add the legend  
        self.ax.legend(loc='upper center',
                       ncol=4,
                       prop=font_manager.FontProperties(size=10))
        # force a draw on the canvas()  
        # trick to show the grid and the legend  
        self.canvas.draw()
        # save the clean background - everything but the line  
        # is drawn and saved in the pixel buffer background  
        self.bg = self.canvas.copy_from_bbox(self.ax.bbox)
        # bind events coming from timer with id = TIMER_ID  
        # to the onTimer callback function  
        wx.EVT_TIMER(self, TIMER_ID, self.onTimer)

    def onTimer(self, evt):
        """callback function for timer events"""
        # restore the clean background, saved at the beginning  
        self.canvas.restore_region(self.bg)

        # update the data 
        #temp =np.random.randint(10,80)
        #self.user = self.user[1:] + [temp*300/100]
        #self.user_1 = self.user_1[1:] + [temp*200/100]
        global x_data
        global y_data
        global z_data
        self.user = x_data
        self.user_1 = y_data
        self.user_2 = z_data
        # update the plot  
        self.l_user.set_ydata(self.user)
        self.l_user_1.set_ydata(self.user_1)
        self.l_user_2.set_ydata(self.user_2)
        # just draw the "animated" objects  
        self.ax.draw_artist(self.l_user)# It is used to efficiently update Axes data (axis ticks, labels, etc are not updated)  
        self.ax.draw_artist(self.l_user_1)# It is used to efficiently update Axes data (axis ticks, labels, etc are not updated)  
        self.ax.draw_artist(self.l_user_2)# It is used to efficiently update Axes data (axis ticks, labels, etc are not updated)  
        self.canvas.blit(self.ax.bbox)

def test():
    global ble_mac
    global ble_conn
    global sub_thread 
    global do_exit
    # test
    ble_mac = "22:01:00:00:03:10" #boss
    ble_mac = "22:01:00:00:03:31"
    ble_mac = "22:01:00:00:03:2A"
    ble_mac = "22:33:44:55:66:88"
    ble_mac = "22:01:00:00:03:16"
    ble_mac = "22:02:04:04:01:03"
    ble_mac = "68:3e:34:fe:0a:99"
    ble_mac = "68:3e:34:fe:0a:EF"
    ble_mac = "22:01:00:00:03:1E"
    ble_mac = "68:3e:34:fe:0a:74"
    ble_mac = "68:3e:34:fe:0a:65"
    ble_mac = "22:99:00:00:00:03"

    ble_connect(ble_mac)

    #listenning
    snd_content_str = """\x01\x00"""
    handle = 0x23
    ble_conn.writeCharacteristic((handle+1), snd_content_str)
    time.sleep(0.5)

    handle = 0x27
    ble_conn.writeCharacteristic((handle+1), snd_content_str)
    time.sleep(0.5)

    handle = 0x2b;
    ble_conn.writeCharacteristic((handle+1), snd_content_str)
    time.sleep(0.5)

    ble_conn.setMTU(200);

    handle = 0x2b;
    snd_content_str = """\x33\x10"""
    ble_conn.writeCharacteristic(0x1f, snd_content_str, True)

    count = 0;
    handle = 0x23;
    snd_content_str = "2204020b010400"
    ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)


    #snd_content_str = "220702FF01E0FF070000"
    #ble_conn.writeCharacteristicRaw(0x23, snd_content_str, True)
    #snd_content_str = "220702FF01F0FF070000"
    #ble_conn.writeCharacteristicRaw(0x23, snd_content_str, True)

    #snd_content_str = "220302FD1800"
    #ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
    #snd_content_str = "220402FD260500"
    #ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
    if do_exit:
        count += 1
        print("send time :%d" %count)

        snd_content_str = "2204020b010300"
        ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
        time.sleep(1)

        snd_content_str = "2204020b010400"
        ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
        time.sleep(2)

        snd_content_str = "2203020a0500"
        ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
        time.sleep(1)

        snd_content_str = "2203020d0100"
        ble_conn.writeCharacteristicRaw(handle, snd_content_str, True)
        time.sleep(1)
        ble_disconnect()


    app = wx.PySimpleApp()
    frame = PlotFigure()
    t = wx.Timer(frame, TIMER_ID)
    t.Start(10)
    frame.Show()
    app.MainLoop()


if __name__ == '__main__':
    #rprint("Application Startt\n")
    signal.signal(signal.SIGINT, signal_handler)

    #btle.Debugging = True

    test()

    while not do_exit:
        cmd = raw_input("%s cmd $ " % state)
        argv = cmd.split()
        if process_cmd(argv) == False:
            break
        no_notification = False

    #rprint("Application quit\n")



