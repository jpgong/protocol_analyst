# coding=utf-8
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.filedialog import LoadFileDialog, askopenfile, asksaveasfile
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

import datetime
import easygui
from scapy.layers.inet import *
from scapy.layers.l2 import *

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()

#用来存储抓到的数据包
packet_list = []
#设置一个停止标志位，用来判断是否停止抓包
stop_flag = False
#sniff函数抓取到的数据报数量
receive_packet_count = 0
#显示列表中显示的数据报数量
show_packet_count = 0
#设置抓包开始时间
begin_time = None
#设置抓包大小
total_bytes = 0
#通过sniff抓取的所有包
#total_packet = None


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime

#对点击的协议进行解析
def on_click_packet_list_tree(event):
    """
    数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    #print(selected_item[0])
    packet = packet_list[int(selected_item[0])-1]
    # 推导数据包的协议类型
    proto_names = ['IP', 'TCP', 'UDP', 'Unknown']
    packet_proto = ''
    for pn in proto_names:
        if pn in packet:
            packet_proto = pn
            ip_packet = packet[IP]
            upper_packet = None
            upper_checksum_hand = 0
            if packet_proto == 'TCP':
                upper_packet = packet[TCP]
                x = raw(upper_packet)
                tcp_raw = x[20:]
                upper_checksum_hand = in4_chksum(socket.IPPROTO_TCP, upper_packet, tcp_raw)
            elif packet_proto == 'UDP':
                upper_packet = packet[UDP]
                x = raw(upper_packet)
                udp_raw = x[20:]
                upper_checksum_hand = in4_chksum(socket.IPPROTO_UDP, upper_packet, udp_raw)
            # print('%04x' % ip_packet.chksum)
            # print('%04x' % upper_packet.chksum)
            # 提取IP首部，计算校验和
            x = raw(ip_packet)[0:ip_packet.ihl * 4]
            ipString = ''.join('%02x' % orb(x) for x in x)
            ipbytes = bytearray.fromhex(ipString)
            ip_chksum_hand = IP_headchecksum(ipbytes)
            break

    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())

    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    #print(lines)
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        else:
            #print(packet_dissect_tree.item(last_tree_entry)['text'])
            proto = packet_dissect_tree.item(last_tree_entry)['text']
            if 'IP' in proto:
                if checkOut(ip_chksum_hand):
                    msg = ' [IP checksum correct]'
                else:
                    msg = ' [IP checksum error]'
            elif 'UDP' in proto:
                if checkOut(upper_checksum_hand):
                    msg = ' [checksum correct]'
                else:
                    msg = ' [checksum error]'
            elif 'TCP' in proto:
                if checkOut(upper_checksum_hand):
                    msg = ' [checksum correct]'
                else:
                    msg = ' [checksum error]'
            line = line.strip('  ')
            if line.startswith('chksum    '):
                line += msg
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'

#按照计算公式手动计算IP首部校验和
def IP_headchecksum(IP_head):
    # 校验和字段设为0
    checksum = 0
    # 得到TP头数据的长度
    headlen = len(IP_head)
    if headlen % 2 == 1:
        #
        IP_head += b'\0'
    i = 0
    while i < headlen:
        temp = struct.unpack('!H', IP_head[i:i + 2])[0]
        checksum = checksum + temp
        i = i + 2
    # 将高16bit与低16位bit相加
    checksum = (checksum >> 16) + (checksum & 0xffff)
    # 将进位与高位的16bit与低16bit再相加
    checksum = checksum + (checksum >> 16)
    # 将强制截断的结果返回(按位取反，取低16位）
    return ~checksum & 0xffff

def checkOut(checksum_self):
    if checksum_self == 0000:
        return True
    else:
        return False

# 将离线的pcap格式文件在该分析器中打开
def open_captured_data_to_file():
    global total_packet  # 保存数据包
    #创建打开窗口
    filetypes = [("All Files", '*'), ("Python Files", '*.py', 'TEXT'), ("Text Files", '*.txt', 'TEXT'),
                 ("Config Files", '*.conf', 'TEXT'), ("WireShake", '*.pcap', 'TEXT')]
    fobj = askopenfile(filetypes=filetypes)
    if fobj:
        fileName = fobj.name
    total_packet = rdpcap(fileName)
    #total_packet = sniff(offline='temp.pcap')
    # 设置按钮状态,并初始化
    global receive_packet_count
    global packet_list
    global show_packet_count
    packet_list.clear()
    receive_packet_count = 0
    show_packet_count = 0
    items = packet_list_tree.get_children()
    for item in items:
        packet_list_tree.delete(item)
    packet_list_tree.update_idletasks()

    start_button['state'] = 'disabled'
    pause_button['state'] = 'disabled'
    pause_button['text'] = '暂停'
    stop_button['state'] = 'disabled'
    global begin_time
    begin_time = datetime.datetime.now()
    for item in total_packet:
        packet_list.append(item)
        receive_packet_count += 1
    # 开另外一个线程用来分析数据包
    t2 = analyse_Thread()
    t2.start()

#获得每个包的状态标志位
def getPacketState(packet):
    if stop_flag == True:
        return True
    else:
        return False

#将抓到的数据报存放在列表中,并显示抓包速度
def packet_receive(packet):
    global packet_list
    global begin_time
    global receive_packet_count
    global total_bytes
    if ~stop_flag:
        packet_list.append(packet)
        receive_packet_count += 1
        end_time = datetime.datetime.now()
        # 显示捕获速率
        total_time = (end_time - begin_time).total_seconds()
        if total_time == 0:
            total_time = 2.23E-308  # 当begin_time和end_time相等时，将total_time设为IEEE 745标准中规定的最小浮点数
        total_bytes = total_bytes + len(packet)
        bytes_per_second = total_bytes / total_time / 1024
        status_bar.set('已经捕获了%d个数据包, 捕获了%d个字节，捕获速率为: %0.2fK字节/秒',
                       receive_packet_count, total_bytes, bytes_per_second)
        #在列表中显示抓到的包
        if pause_button['text'] == '暂停':
            # 对抓到的包进行处理
            # 填充数据包列表中的每一项
            packet_time = timestamp2time(packet.time)
            # 推导数据包的协议类型
            proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'OSPF', 'DHCP', 'IPv6', 'DNS', 'Unknown']
            packet_proto = ''
            for pn in proto_names:
                if pn in packet:
                    packet_proto = pn
                    break
            proto = packet_proto
            src = packet.src
            dst = packet.dst
            length = len(packet)
            info = packet.summary()
            packet_list_tree.insert("", 'end', '%s' % (receive_packet_count), text=receive_packet_count,
                                    values=('%s' % (receive_packet_count), packet_time, src, dst, proto, length, info))
            # 更新该列表
            packet_list_tree.update_idletasks()

# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    #输出过滤条件
    filter_condition = fitler_entry.get();
    #print("filter condition:" + filter_condition)
    #设置按钮状态,并初始化
    global receive_packet_count
    global packet_list
    global stop_flag
    global total_bytes

    packet_list.clear()
    receive_packet_count = 0
    stop_flag = False
    total_bytes = 0
    items = packet_list_tree.get_children()
    for item in items:
        packet_list_tree.delete(item)
    packet_list_tree.update_idletasks()

    start_button['state'] = 'disabled'
    pause_button['state'] = 'normal'
    pause_button['text'] = '暂停'
    stop_button['state'] = 'normal'
    open_button['state'] = 'disabled'
    global begin_time
    begin_time = datetime.datetime.now()
    #创建一个线程用来抓包，并处理抓到的数据包
    t1 = receive_Thread(filter_condition)
    t1.start()

#创建一个线程用来处理离线数据包
class analyse_Thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global show_packet_count
        global receive_packet_count
        global packet_list
        while True:
            if receive_packet_count > show_packet_count:
                packet = packet_list[show_packet_count]
                show_packet_count += 1
                # 对抓到的包进行处理
                # 填充数据包列表中的每一项
                packet_time = timestamp2time(packet.time)
                # 推导数据包的协议类型
                proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'OSPF', 'DHCP', 'IPv6', 'Unknown']
                packet_proto = ''
                for pn in proto_names:
                    if pn in packet:
                        packet_proto = pn
                        break
                proto = packet_proto
                src = packet.src
                dst = packet.dst
                length = len(packet)
                info = packet.summary()
                packet_list_tree.insert("", 'end', '%s' % (show_packet_count), text=show_packet_count,
                                        values=('%s' % (show_packet_count), packet_time, src, dst, proto, length, info))
                # 更新该列表
                packet_list_tree.update_idletasks()
            else:
                break;

#创建一个抓包线程,将抓到的数据包存放列表中
#线程创建形式和java类似
class receive_Thread(threading.Thread):
    def __init__(self, filter_condition):
        threading.Thread.__init__(self)
        self.filter_condition = filter_condition
    def run(self):
        global total_packet
        total_packet = sniff(filter=self.filter_condition, stop_filter=(lambda x: getPacketState(x)),
                             prn=(lambda x: packet_receive(x)))

#暂停按钮单击响应函数，只是停止在数据列表中显示，而不是停止sniff函数
#即只是往list中存放数据包而已
def pause_capture():
    #只是不在页面显示抓到的数据包
    if pause_button['text'] == '暂停':
        pause_button['text'] = '继续'
    elif pause_button['text'] == '继续':
        pause_button['text'] = '暂停'

# 停止按钮单击响应函数,
def stop_capture():
    global stop_flag
    stop_flag = True

    start_button['state'] = 'normal'
    pause_button['state'] = 'normal'
    stop_button['state'] = 'disable'
    open_button['state'] = 'normal'
    status_bar.set("%s", '开始')
    #停止抓包时提示用户是否要保存抓取的数据包
    global total_packet  # 保存数据包
    fobj = asksaveasfile()
    if fobj:
        filename = fobj.name
        #print(filename)
        wrpcap(filename, total_packet)

# 退出按钮单击响应函数，退出该程序
def quit_program():
    os._exit(0)

# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
open_button = Button(toolbar, width=8, text="打开文件", command=open_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
open_button['state'] = 'normal'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
open_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=open_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)
main_panedwindow.pack(fill=BOTH, expand=1)
# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')
tk.mainloop()

