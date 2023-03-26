import imp
from Gui import *
from SnifferController import *
from Sniffer import *
import sys
import os


if __name__ == "__main__":
    try:
        os.chdir(sys.path[0])
        app = QtWidgets.QApplication(sys.argv)
        ui = Gui()  # start GUI
        MainWindow = QtWidgets.QMainWindow()
        ui.setupUi(MainWindow)
        MainWindow.show()
        sc = SnifferController(ui) # begin to sniff
        sc.loadAdapterIfaces()
        sc.setConnection()
        sys.exit(app.exec_())
    except Exception as e:
        QtWidgets.QMessageBox.critical(None, "Error: ", str(e))
    