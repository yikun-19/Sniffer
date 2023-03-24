# -*- coding: utf-8 -*-

from socket import timeout
from scapy.all import *
import os
import time
import multiprocessing
from scapy.layers import http
import numpy as np
import matplotlib.pyplot as plt
import binascii
from PyQt5 import QtCore,QtGui,QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *


class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.packet.Packet) 
    def __init__(self) -> None:
        super().__init__()
        self.filter = None              # filter rule
        self.iface = None               # network interface
        self.conditionFlag = False      # pause flag
        self.trace_flag = False
        self.trace_key = None
        self.trace_content = None
        self.mutex_1 = QMutex()
        self.cond = QWaitCondition()
        

    def run(self):
        while True :
            self.mutex_1.lock()
            if self.conditionFlag :
                self.cond.wait(self.mutex_1)
            print('Sniffing device name is : ' + self.iface)
            self.iface = r'WLAN'
            sniff(filter=self.filter, iface=self.iface, prn=lambda x:self.HandleSignal.emit(x), count = 1, timeout = 2)
            self.mutex_1.unlock()
            

    def pause(self):
        self.conditionFlag = True  # Sniffer is paused. 

    def resume(self):
        self.conditionFlag = False
        self.cond.wakeAll()   

'''test 
ifa = "Intel(R) Dual Band Wireless-AC 3168"
pkg = sniff(iface=ifa,count = 1) 
'''   
    



