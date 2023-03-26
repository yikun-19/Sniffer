from ast import dump
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from scapy.all import *
import sys
import os
import time

class Gui(object):
    def setupUi(self, MainWindow):
        self.MainWindow = MainWindow
        self.startTime = None
        self.filter = None
        self.iface = None
        self.packList = []
        global counts
        counts = 0
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1400, 800)
        MainWindow.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.gridLayoutBar = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayoutBar.setObjectName("gridLayoutBar")

        self.gridLayoutMainShow = QtWidgets.QGridLayout()
        self.gridLayoutMainShow.setObjectName("gridLayoutMainShow")

        # Packet in Binary
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")

        self.textBrowserShow = QtWidgets.QTextBrowser(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(3)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.textBrowserShow.sizePolicy().hasHeightForWidth())
        self.textBrowserShow.setSizePolicy(sizePolicy)
        self.textBrowserShow.setObjectName("textBrowserShow")
        self.horizontalLayout.addWidget(self.textBrowserShow)

        self.gridLayoutMainShow.addLayout(self.horizontalLayout, 2, 0, 1, 1)


        # Packet Details
        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(3)
        sizePolicy.setVerticalStretch(2)
        sizePolicy.setHeightForWidth(self.treeWidget.sizePolicy().hasHeightForWidth())
        self.treeWidget.setSizePolicy(sizePolicy)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.headerItem().setText(0, "root")
        self.gridLayoutMainShow.addWidget(self.treeWidget, 1, 0, 1, 1)


        # Packet List
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(3)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(6, item)
        self.gridLayoutMainShow.addWidget(self.tableWidget, 0, 0, 1, 1)
        self.tableWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.contextMenu = QMenu(self.tableWidget)
        self.saveAction = self.contextMenu.addAction(u'save')
        self.TraceAction = self.contextMenu.addAction(u'trace(TCP)')
        
        self.gridLayoutBar.addLayout(self.gridLayoutMainShow, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.toolbar = QtWidgets.QToolBar(MainWindow)
        self.toolbar.setObjectName("toolbar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolbar)
        self.toolbar.addSeparator()

        self.comboBoxIfaces = QComboBox()
        self.toolbar.addWidget(self.comboBoxIfaces)
        self.toolbar.addSeparator()

        QToolTip.setFont(QFont('SansSerif', 10))

        self.buttonStart = QtWidgets.QPushButton()
        self.buttonStart.setIcon(QIcon("./icons/start.jpeg"))
        self.buttonStart.setStyleSheet("background:rgba(0,0,0,0);"
                                        "border:3px solid rgba(0,0,0,0);"
                                        "border-radius:10px;")
        self.toolbar.addWidget(self.buttonStart)
        self.toolbar.addSeparator()

        self.buttonPause = QtWidgets.QPushButton()
        self.buttonPause.setIcon(QIcon("./icons/pause.jpeg"))
        self.buttonPause.setStyleSheet("background:rgba(0,0,0,0);"
                                        "border:3px solid rgba(0,0,0,0);"
                                        "border-radius:10px;")
        self.toolbar.addWidget(self.buttonPause)
        self.toolbar.addSeparator()

        self.buttonFilter = QtWidgets.QPushButton()
        self.buttonFilter.setIcon(QIcon("./icons/filter.jpeg"))
        self.buttonFilter.setStyleSheet("background:rgba(0,0,0,0);"
                                        "border:3px solid rgba(0,0,0,0);"
                                        "border-radius:10px;")
        self.toolbar.addWidget(self.buttonFilter)
        self.toolbar.addSeparator()
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Simple Sniffer"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Source"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length"))
        item = self.tableWidget.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Info"))
        self.buttonStart.setText(_translate("MainWindow", "Start"))
        self.buttonPause.setText(_translate("MainWindow", "Pause"))
        self.buttonFilter.setText(_translate("MainWindow", "Filter"))

        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows) 
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setColumnWidth(0, 60)
        self.tableWidget.setColumnWidth(2, 200)
        self.tableWidget.setColumnWidth(3, 200)
        self.tableWidget.setColumnWidth(4, 100)
        self.tableWidget.setColumnWidth(5, 60)
        self.tableWidget.setColumnWidth(6, 600)

        self.treeWidget.setHeaderHidden(True)
        self.treeWidget.setColumnCount(1)

        self.timer = QTimer(self.MainWindow)
        self.timer.timeout.connect(self.statistics)
        self.timer.start(1000)

    def showContextMenu(self):
        self.contextMenu.exec_(QCursor.pos()) # when right button click

    def setAdapterIfaces(self, c):
        self.comboBoxIfaces.addItems(c)

    def setTableItems(self, res):
        global counts
        counts += 1
        if res :
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(str(counts)))
            self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(res[0]))
            self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(res[1]))
            self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(res[2]))
            self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(res[3]))
            self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(res[4]))
            self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(res[5]))
            self.packList.append(res[6])
    
    def setLayer_5(self,row,times):
        num = self.tableWidget.item(row, 0).text()
        Time = self.tableWidget.item(row, 1).text()
        length = self.tableWidget.item(row, 5).text()
        iface = self.iface
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(times))
        Frame = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Frame.setText(0, 'Frame %s: %s bytes on %s' % (num,length,iface))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0, 'Device: %s' % iface)
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0, 'Arrive time: %s' % timeformat)
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0, 'Time after first: %s' % Time)
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0, 'Number: %s' % num)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0, 'Frame length: %s' % length)

    def setLayer_4(self,packet):
        if packet.layer_4['name']  == 'Ethernet':
            Ethernet_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Ethernet_.setText(0, packet.layer_4['info'])
            EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetDst.setText(0, 'Destination MAC address: '+ packet.layer_4['dst'])
            EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetSrc.setText(0, 'Source MAC address: '+ packet.layer_4['src'])
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet_)
            EthernetType.setText(0, 'Protocol: '+ packet.layer_3['name'])
        elif packet.layer_4['name']  == 'Loopback':
            Loopback_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            Loopback_.setText(0, packet.layer_4['info'])
            LoopbackType = QtWidgets.QTreeWidgetItem(Loopback_)
            LoopbackType.setText(0, 'Protocol: '+ packet.layer_3['name'])
        
    def setLayer_3(self,packet):
        if packet.layer_3['name'] == 'IPv4':
            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0, packet.layer_3['info'])
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0, 'Version: %s'% packet.layer_3['version'])
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0, 'Header length: %s' % packet.layer_3['ihl'])
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0, 'TOS: %s'% packet.layer_3['tos'])
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0, 'Len: %s' % packet.layer_3['len'])
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0, 'ID: %s' % packet.layer_3['id'])
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0, 'flags: %s' % packet.layer_3['flag'])
            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0, 'CheckSum: 0x%x' % packet.layer_3['chksum'])
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0, 'Source IP address: %s' % packet.layer_3['src'])
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0, 'Destination IP address: %s' % packet.layer_3['dst'])
            IPv4Options = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Options.setText(0, 'Options: %s' % packet.layer_3['opt'])
            IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Proto.setText(0, 'Protocol: %s' % packet.layer_2['name'])
        elif packet.layer_3['name'] == 'IPv6':
            IPv6_ = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv6_.setText(0, packet.layer_3['info'])
            IPv6Version = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Version.setText(0, 'Version: %s'% packet.layer_3['version'])
            IPv6Src = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Src.setText(0, 'Source IP address: %s' % packet.layer_3['src'])
            IPv6Dst = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Dst.setText(0, 'Destination IP address: %s' % packet.layer_3['dst'])
            IPv6Proto = QtWidgets.QTreeWidgetItem(IPv6_)
            IPv6Proto.setText(0, 'Protocol: '+ packet.layer_2['name'])
        elif packet.layer_3['name'] == 'ARP':
            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0, packet.layer_3['name'] + " "+ packet.layer_3['info'])
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0, 'HW Type: 0x%x' % packet.layer_3['hwtype'])
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0, 'Protocol number: 0x%x' % packet.layer_3['ptype'])
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0, 'HW address length: %s' % packet.layer_3['hwlen'])
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0, 'Protocol length: %s' % packet.layer_3['len'])
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            arpOp.setText(0, 'OP Type: %s' % packet.layer_3['info'])
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0, 'Source MAC address: %s' % packet.layer_3['hwsrc'])
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0, 'Source IP address: %s' % packet.layer_3['src'])
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0, 'Destination MAC address: %s' % packet.layer_3['hwdst'])
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0, 'Destination IP address: %s' % packet.layer_3['dst'])

    def setLayer_2(self,packet):
        if packet.layer_2['name'] == 'TCP':
            tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            tcp.setText(0, packet.layer_2['info'])
            tcpSport = QtWidgets.QTreeWidgetItem(tcp)
            tcpSport.setText(0, 'Source Port: %s' % packet.layer_2['src'])
            tcpDport = QtWidgets.QTreeWidgetItem(tcp)
            tcpDport.setText(0, 'Destination Port: %s' % packet.layer_2['dst'])
            tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
            tcpSeq.setText(0, 'Seq: %s' % packet.layer_2['seq'])
            tcpAck = QtWidgets.QTreeWidgetItem(tcp)
            tcpAck.setText(0, 'Ack: %s' % packet.layer_2['ack'])
            tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
            tcpDataofs.setText(0, 'Data offset: %s' % packet.layer_2['dataofs'])
            tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
            tcpReserved.setText(0, 'Reserved: %s' % packet.layer_2['reserved'])
            tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
            tcpFlags.setText(0, 'Flag: %s' % packet.layer_2['flag'])
        elif packet.layer_2['name'] == 'UDP':
            udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            udp.setText(0, packet.layer_2['info'])
            udpSport = QtWidgets.QTreeWidgetItem(udp)
            udpSport.setText(0, 'Source port: %s' % packet.layer_2['src'])
            udpDport = QtWidgets.QTreeWidgetItem(udp)
            udpDport.setText(0, 'Destination port: %s' % packet.layer_2['dst'])
            udpLen = QtWidgets.QTreeWidgetItem(udp)
            udpLen.setText(0, 'Length: %s' % packet.layer_2['len'])
            udpChksum = QtWidgets.QTreeWidgetItem(udp)
            udpChksum.setText(0, 'CheckSum: 0x%x' % packet.layer_2['chksum'])
        elif packet.layer_2['name'] == 'ICMP':
            icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            icmp.setText(0, 'ICMP')
            icmpType = QtWidgets.QTreeWidgetItem(icmp)
            icmpType.setText(0, 'Type: %s' % packet.layer_2['info'])
            icmpCode = QtWidgets.QTreeWidgetItem(icmp)
            icmpCode.setText(0, 'Code: %s' % packet.layer_2['code'])
            icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
            icmpChksum.setText(0, 'CheckSum: 0x%x' % packet.layer_2['chksum'])
            icmpId = QtWidgets.QTreeWidgetItem(icmp)
            icmpId.setText(0, 'ID: %s' % packet.layer_2['id'])
        elif packet.layer_2['name'] == 'IGMP':
            igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            igmp.setText(0, packet.layer_2['info'])
            igmpLength = QtWidgets.QTreeWidgetItem(igmp)
            igmpLength.setText(0, 'Length: %s' % packet.layer_2['len'])
        else:
            waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
            waitproto.setText(0, 'Protocol: %s' % packet.layer_2['name'])
            waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
            waitprotoInfo.setText(0, packet.layer_2['info'])

    def setLayer_1(self,packet):
        waitproto =  QtWidgets.QTreeWidgetItem(self.treeWidget)
        waitproto.setText(0, packet.layer_1['name'])
        waitprotoInfo = QtWidgets.QTreeWidgetItem(waitproto)
        waitprotoInfo.setText(0, packet.layer_1['info'])

    def showItemDetail(self):
        row = self.tableWidget.currentRow() 
        mypacket = self.packList[row]

        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)
        self.setLayer_5(row,mypacket.packet.time) 
        self.setLayer_4(mypacket)
        self.setLayer_3(mypacket)
        if mypacket.layer_2['name'] is not None:
            self.setLayer_2(mypacket)
        if mypacket.layer_1['name'] is not None:
            self.setLayer_1(mypacket)

        # Packet in Binary
        self.textBrowserShow.clear()
        content = hexdump(mypacket.packet, dump=True)
        self.textBrowserShow.append(content)
        
       
    def statistics(self):
        global counts
        if counts != 0:
            self.statusbar.showMessage('Capture: %s' % (counts))

    def clearTable(self):
        global counts
        counts = 0
        self.tableWidget.setRowCount(0)
        self.treeWidget.clear()
        self.textBrowserShow.clear()
        self.packList = []

    def simpleFilter(self):
        list = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol type']   
        item, ok = QInputDialog.getItem(self.MainWindow, "Filter", "Rules", list, 1, False)
        if ok:
            if item == 'Protocol type':
                filter, ok_0 = QInputDialog.getText(self.MainWindow, 'Hello!', "Pls input Protocol type: ", QLineEdit.Normal, 'TCP/UDP/HTTP/TLS/ICMP/...')
                rule = filter
            elif item == 'Source IP':
                filter, ok_1 = QInputDialog.getText(self.MainWindow, 'Hello!', 'Pls input Source IP: ', QLineEdit.Normal, '0.0.0.0')
                rule = 'src host ' + filter
            elif item == 'Destination IP'  :
                filter, ok_2 = QInputDialog.getText(self.MainWindow, 'Hello!', 'Pls input Destination IP: ', QLineEdit.Normal, '0.0.0.0')
                rule = 'dst host ' + filter
            elif item == 'Source Port':
                filter, ok_3 = QInputDialog.getInt(self.MainWindow, 'Hello!', 'Pls input Source Port: ', 80, 0, 65535)
                rule = 'src port ' + str(filter)
            elif item == 'Destination Port':
                filter, ok_4 = QInputDialog.getInt(self.MainWindow, 'Hello!', 'Pls input Destination Port: ', 80, 0, 65535)
                rule = 'dst port ' + str(filter)
            else:
                rule = ''
            rule = rule.lower()
            self.filter = rule

    def Trace(self): # TODO: should pause before
        row = self.tableWidget.currentRow()
        if self.packList[row].layer_2['name'] == 'TCP':
            list = ['IP + Port', 'Source IP + Source Port']   
            item, ok = QInputDialog.getItem(self.MainWindow, 'Trace for TCP', 'Rules', list, 1, False)
            if ok:
                if item == 'IP + Port':
                    keys = 'tcptrace'
                elif item == 'Source IP + Source Port':
                    keys = 'tcpSdTrace'  
                mypacket = self.packList[row]
                QtWidgets.QMessageBox.information(None, 'Good!', 'Pls click start button!')
                return [True, keys, mypacket.layer_2[keys]]
        else:
            QtWidgets.QMessageBox.critical(None, 'Sorry!', 'Trace for only TCP flow now!')

    