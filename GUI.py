import easygui as g
import os
import sys
import time
import threading
from tkinter import *

def update_progress_bar():
    for percent in range(1, 101):
        second = percent % 100
        green_length = int(sum_length * percent / 100)
        canvas_progress_bar.coords(canvas_shape, (0, 0, green_length, 25))
        canvas_progress_bar.itemconfig(canvas_text, text='当前抓包进度：%02d' % (second))
        var_progress_bar_percent.set('%0.2f  %%' % percent)
        time.sleep(0.1)
    top.quit()

def getResult():    
    os.system("main.exe")

begin = g.ccbox(msg='是否开始使用？', title='开始界面', choices=('是', '否'), image=None)
if begin == True:
    # 
    os.system("gcc main.cpp -o main -lwpcap -lws2_32")
    # 
    devicenum = g.enterbox(msg='输入想要监听的设备编号?', title='我是一个询问框', default='4', strip=True, image=None, root=None)
    f = open('readchoice.txt', 'w')
    f.write(devicenum)
    f.close()
    
    top = Tk()
    top.title('Progress Bar')
    top.geometry('800x50+290+100')
    top.resizable(False, False)
    top.config(bg='#535353')
    # 进度条
    sum_length = 630
    canvas_progress_bar = Canvas(top, width=sum_length, height=20)
    canvas_shape = canvas_progress_bar.create_rectangle(0, 0, 0, 25, fill='green')
    canvas_text = canvas_progress_bar.create_text(292, 4, anchor=NW)
    canvas_progress_bar.itemconfig(canvas_text, text='当前抓包个数：0')
    var_progress_bar_percent = StringVar()
    var_progress_bar_percent.set('00.00  %')
    label_progress_bar_percent = Label(top, textvariable=var_progress_bar_percent, fg='#F5F5F5', bg='#535353')
    canvas_progress_bar.place(relx=0.45, rely=0.4, anchor=CENTER)
    label_progress_bar_percent.place(relx=0.89, rely=0.4, anchor=CENTER)
    if devicenum != 0:
        th1 = threading.Thread(target=update_progress_bar)
        th1.setDaemon(True)
        th1.start()
        # 注意加入主循环的位置
        top.mainloop()
        th1.join()
        th2 = threading.Thread(target=getResult)
        th2.setDaemon(True)
        th2.start()
        th1.join()
        th2.join()

        if th1.isAlive() == False and th2.isAlive() == False:
            f = open('result.txt', encoding='utf-8', errors= 'ignore')
            result = f.read()
            f.close()
            showresult = g.textbox(msg='抓包与分析情况如下：', title='我是一个询问框', text=result, codebox=0) 
else:
    sys.exit(0)