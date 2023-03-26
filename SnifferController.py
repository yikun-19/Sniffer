from PyQt5.QtWidgets import *
from Sniffer import *
from Gui import *
import time
from parsePacket import *


class SnifferController():
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

    def getAdapterIfaces(self):
        c = []
        for i in repr(conf.route).split('\n')[1:]:
            tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]', i).group()[0:44].rstrip()
            if len(tmp)>0:
                c.append(tmp)
        c = list(set(c))
        return c

    def loadAdapterIfaces(self):
        ifaces  = self.getAdapterIfaces()
        self.ui.setAdapterIfaces(ifaces)
    
    def setConnection(self):
        self.ui.buttonStart.clicked.connect(self.Start)    
        self.ui.buttonPause.clicked.connect(self.Stop)
        self.ui.buttonFilter.clicked.connect(self.Filter)
        self.ui.tableWidget.itemClicked.connect(self.ui.showItemDetail)
        self.ui.tableWidget.customContextMenuRequested.connect(self.ui.showContextMenu)
        self.ui.TraceAction.triggered.connect(self.Trace)
        self.ui.saveAction.triggered.connect(self.Save)
    
    def Start(self):
        if self.sniffer is None:
            self.ui.startTime = time.time()
            self.sniffer = Sniffer()
            self.setSniffer()
            self.sniffer.HandleSignal.connect(self.myCallBack)   # HandleSignal emits sniffer packets to CallBack function
            self.sniffer.start()  # Note: Sniffer is a thread, so start() not run()! 
            print('====== Start sniffing! ======')
        elif self.sniffer.conditionFlag :
            if self.ui.iface != self.ui.comboBoxIfaces.currentText() or self.sniffer.filter != self.ui.filter :
                print('====== Sniffing device is changed! ======')
                self.setSniffer()
                self.ui.clearTable()
            self.sniffer.resume()
        else:
            print('Sniffer is already running!')

    def setSniffer(self):
        self.sniffer.filter = self.ui.filter
        self.sniffer.iface = self.ui.comboBoxIfaces.currentText()  # click to choose the target device
        self.ui.iface = self.ui.comboBoxIfaces.currentText()
    
    def myCallBack(self, packet):
        if self.ui.filter ==  'http' or self.ui.filter ==  'https':
            if packet.haslayer('TCP') ==False:
                return
            if packet[TCP].dport != 80 and packet[TCP].sport != 80 and packet[TCP].dport != 443 and packet[TCP].sport != 443:
                return                
        res = []
        myPacket = MyPacket()
        myPacket.parse(packet, self.ui.startTime)
        packetTime = myPacket.packTimne
        lens = myPacket.lens
        src = myPacket.layer_3['src']
        dst = myPacket.layer_3['dst']
        type = None
        info = None
        if myPacket.layer_1['name'] is not None:
            type = myPacket.layer_1['name']
            info = myPacket.layer_1['info']
        elif myPacket.layer_2['name'] is not None:
            type = myPacket.layer_2['name']
            info = myPacket.layer_2['info']
        elif myPacket.layer_3['name'] is not None:
            type = myPacket.layer_3['name']
            info = myPacket.layer_3['info']

        res.append(packetTime)
        res.append(src)
        res.append(dst)
        res.append(type)
        res.append(lens)
        res.append(info)
        res.append(myPacket)
        print('  == A packet is caught! == ')
        print(str(packetTime) + ' ' + str(src) + ' ' + str(dst) + ' ' + type + ' ' + str(lens) + ' ' + str(info))
        if self.sniffer.trace_flag == False or myPacket.layer_2[self.sniffer.trace_key] == self.sniffer.trace_content:  # TODO: 
            self.ui.setTableItems(res)

    def PostFilter(self):
        self.ui.postFilter()
    
    def Stop(self):
        self.sniffer.pause()

    def Filter(self):
        self.ui.simpleFilter()
    
    def Trace(self):
        res = self.ui.Trace()
        self.sniffer.trace_flag = res[0]
        self.sniffer.trace_key = res[1]
        self.sniffer.trace_content = res[2]
        self.ui.clearTable()
    
    def Save(self):
        try:
            row = self.ui.tableWidget.currentRow() 
            packet = self.ui.packList[row].packet
            path, filetype = QtWidgets.QFileDialog.getSaveFileName(None, 'Pls choose a path', './', '.pcap')
            if path == '':
                return
            if os.path.exists(os.path.dirname(path)) == False:
                QtWidgets.QMessageBox.critical(None, 'Sorry!', 'This path does not exist.')
                return
        
            wrpcap(path,packet)
            QtWidgets.QMessageBox.information(None, 'OK!', 'Saved!')
        except ImportError as  e:
            QtWidgets.QMessageBox.critical(None, 'Error: ', str(e))
 
