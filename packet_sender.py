# coding=utf-8
import datetime
import tkinter
from tkinter import *
from tkinter.constants import *
from tkinter.ttk import Treeview, Style

from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import *
from scapy.layers.l2 import *


tk = tkinter.Tk()
tk.title("协议编辑器")
# tk.geometry("1000x700")
# 使窗体最大化
tk.state("zoomed")
# 左右分隔窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5)
# 协议编辑区窗体
protocol_editor_panedwindow = PanedWindow(orient=VERTICAL, sashrelief=RAISED, sashwidth=5)
# 协议导航树
protocols_tree = Treeview()
# 当前网卡的默认网关
default_gateway = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-3]
# 用来终止数据包发送线程的线程事件
stop_sending = threading.Event()

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

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')

def create_protocols_tree():
    """
    创建协议导航树
    :return: 协议导航树
    """
    protocols_tree.heading('#0', text='选择网络协议', anchor='w')
    # 参数:parent, index, iid=None, **kw (父节点，插入的位置，id，显示出的文本)
    # 应用层
    applicatoin_layer_tree_entry = protocols_tree.insert("", 0, "应用层", text="应用层")  # ""表示父节点是根
    http_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "HTTP包", text="HTTP包")
    dns_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "DNS包", text="DNS包")
    # 传输层
    transfer_layer_tree_entry = protocols_tree.insert("", 1, "传输层", text="传输层")
    tcp_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 0, "TCP包", text="TCP包")
    upd_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 1, "UDP包", text="UDP包")
    # 网络层
    ip_layer_tree_entry = protocols_tree.insert("", 2, "网络层", text="网络层")
    ip_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 0, "IP包", text="IP包")
    icmp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 1, "ICMP包", text="ICMP包")
    arp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 2, "ARP包", text="ARP包")
    # 网络接入层
    ether_layer_tree_entry = protocols_tree.insert("", 3, "网络接入层", text="网络接入层")
    mac_frame_tree_entry = protocols_tree.insert(ether_layer_tree_entry, 1, "MAC帧", text="MAC帧")
    protocols_tree.bind('<<TreeviewSelect>>', on_click_protocols_tree)
    style = Style(tk)
    # get disabled entry colors
    disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
    style.map("Treeview",
              fieldbackground=[("disabled", disabled_bg)],
              foreground=[("disabled", "gray")],
              background=[("disabled", disabled_bg)])
    protocols_tree.pack()
    return protocols_tree

def create_protocol_editor(root, field_names):
    """
    创建协议字段编辑区
    :param root: 协议编辑区
    :param field_names: 协议字段名列表
    :return: 协议字段编辑框列表
    """
    entries = []
    for field in field_names:
        row = Frame(root)
        label = Label(row, width=20, text=field, anchor='e')
        entry = Entry(row, font=('Courier', '12', 'bold'), state='normal')  # 设置编辑框为等宽字体
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
        entries.append(entry)
    return entries

#清空每个Entry中的值
def clear_protocol_entry(entry):
    # 如果有只读Entry，也要清空它的当前值
    state = entry['state']
    entry['state'] = 'normal'
    entry.delete(0, END)
    entry['state'] = state
    
def clear_protocol_editor(entries):
    """
    清空协议编辑器的当前值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    for entry in entries:
        clear_protocol_entry(entry)
def clear_upper_protocol_editor(entries, entries_upper):
    for entry in entries:
        clear_protocol_entry(entry)
    for entry in entries_upper:
        clear_protocol_entry(entry)
def clear_third_protocol_editor(entries, entries_upper, entries_third):
    for entry in entries:
        clear_protocol_entry(entry)
    for entry in entries_upper:
        clear_protocol_entry(entry)
    for entry in entries_third:
        clear_protocol_entry(entry)

def create_bottom_buttons(root):
    """
    创建发送按钮和重置按钮
    :param root: 编辑编辑区
    :return: 发送按钮和清空按钮
    """
    bottom_buttons = Frame(root)
    send_packet_button = Button(bottom_buttons, width=20, text="发送")
    default_packet_button = Button(bottom_buttons, width=20, text="默认值")
    reset_button = Button(bottom_buttons, width=20, text="重置")
    bottom_buttons.pack(side=BOTTOM, fill=X, padx=5, pady=5)
    send_packet_button.grid(row=0, column=0, padx=5, pady=5)
    default_packet_button.grid(row=0, column=1, padx=2, pady=5)
    reset_button.grid(row=0, column=2, padx=5, pady=5)
    bottom_buttons.columnconfigure(0, weight=1)
    bottom_buttons.columnconfigure(1, weight=1)
    bottom_buttons.columnconfigure(2, weight=1)
    return send_packet_button, reset_button, default_packet_button

def toggle_protocols_tree_state():
    """
    使protocols_tree失效
    :rtype: None
    """
    if "disabled" in protocols_tree.state():
        protocols_tree.state(("!disabled",))
        # re-enable item opening on click
        protocols_tree.unbind('<Button-1>')
    else:
        protocols_tree.state(("disabled",))
        # disable item opening on click
        protocols_tree.bind('<Button-1>', lambda event: 'break')

def on_click_protocols_tree(event):
    """
    协议导航树单击事件响应函数
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空protocol_editor_panedwindow上现有的控件
    for widget in protocol_editor_panedwindow.winfo_children():
        #print(widget)
        widget.destroy()
    # 设置状态栏
    status_bar.set("%s", selected_item[0])

    if selected_item[0] == "MAC帧":
        create_mac_sender()
    elif selected_item[0] == "ARP包":
        create_arp_sender()
    elif selected_item[0] == "ICMP包":
        create_icmp_sender()
    elif selected_item[0] == "IP包":
        create_ip_sender()
    elif selected_item[0] == "TCP包":
        create_tcp_sender()
    elif selected_item[0] == "UDP包":
        create_udp_sender()
    elif selected_item[0] == "HTTP包":
        pass
        # create_http_sender()
    elif selected_item[0] == "DNS包":
        create_dns_sender()

def create_mac_sender():
    """
    创建MAC帧编辑器
    :return: None
    """
    # MAC帧编辑区
    mac_fields = '源MAC地址(6 bytes)：', '目标MAC地址(6 bytes)：', '协议类型(2 bytes)：', '自定义数据：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送MAC帧
    tk.bind('<Return>', (lambda event: send_mac_frame(entries, send_packet_button)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送MAC帧
    send_packet_button.bind('<Button-1>', (lambda event: send_mac_frame(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入MAC帧字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_mac_frame(entries)))

def create_default_mac_frame(entries):
    """
    在协议字段编辑框中填入默认MAC帧的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_mac_frame = Ether()
    entries[0].insert(0, default_mac_frame.src)
    entries[1].insert(0, default_mac_frame.dst)
    entries[2].insert(0, hex(default_mac_frame.type))

def send_mac_frame(entries, send_packet_button):
    """
    发送MAC帧
    :param send_packet_button: MAC帧发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        mac_src = entries[0].get()
        mac_dst = entries[1].get()
        mac_type = int(entries[2].get(), 16)
        mac_data = entries[3].get()
        packet_to_send = Ether(src=mac_src, dst=mac_dst, type=mac_type)
        print(packet_to_send.show2())
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send/mac_data,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def create_arp_sender():
    #创建ARP包编辑器
    # ARP包编辑区
    arp_fields = '硬件类型(2 bytes)：', '协议类型(2 bytes)：', '硬件地址长度(1 bytes)：', '协议地址长度(1 bytes)：', \
                 '操作码(2 bytes)：', '源硬件地址(6 bytes)：', '源逻辑地址(4 bytes)：', '目标硬件地址(6 bytes)：', \
                 '目标逻辑地址(4 bytes)：'
    entries = create_protocol_editor(protocol_editor_panedwindow, arp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    tk.bind('<Return>', (lambda event: send_arp_packet(entries, send_packet_button)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>', (
        lambda event: send_arp_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_arp_packet(entries)))

def create_default_arp_packet(entries):
    """
    在协议字段编辑框中填入默认ARP包的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_arp_packet = ARP()
    entries[0].insert(0, default_arp_packet.hwtype)
    entries[1].insert(0, hex(default_arp_packet.ptype))
    entries[2].insert(0, default_arp_packet.hwlen)
    entries[3].insert(0, default_arp_packet.plen)
    entries[4].insert(0, default_arp_packet.op)
    entries[5].insert(0, default_arp_packet.hwsrc)
    entries[6].insert(0, default_arp_packet.psrc)
    entries[7].insert(0, default_arp_packet.hwdst)
    # 目标IP地址设成本地默认网关
    entries[8].insert(0, default_gateway)

def send_arp_packet(entries, send_packet_button):
    """
    发送ARP包
    :param send_packet_button: ARP包发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        arp_hwtype = int(entries[0].get())
        arp_ptype = int(entries[1].get(), 16)
        arp_hwlen = int(entries[2].get())
        arp_plen = int(entries[3].get())
        arp_op = int(entries[4].get())
        arp_hwsrc = entries[5].get()
        arp_psrc = entries[6].get()
        arp_hwdst = entries[7].get()
        arp_pdst = entries[8].get()
        packet_to_send = ARP(hwtype=arp_hwtype, ptype=arp_ptype, hwlen=arp_hwlen, plen=arp_plen,
                             op=arp_op, hwsrc=arp_hwsrc, psrc=arp_psrc, hwdst=arp_hwdst, pdst=arp_pdst)
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def create_icmp_sender():
    # ICMP包编辑区,'数据负载：',
    ip_fields = '版本(4 bits)：', '首部长度(4 bits)：', '区分服务(8 bits)：', '总长度(16 bits)：', '标识(16 bits)：', \
                 '标志(3 bits)：', '片偏移(13 bits)：', '生存时间(8 bits)：', '协议(8 bits)：', '首部校验和(16 bits):', \
                 '源地址(32 bits):', '目的地址(32 bits):'
    icmp_fields = '类型(8 bits):','代码(8 bits):','校验和(16 bits):','标识号(16 bits):','序列号(16 bits):','自定义数据：'
    # 将IP编辑区放到协议编辑区里面主
    top_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*5/9)
    top_editor.pack(side=TOP, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(top_editor)
    # 将ICMP编辑区放到协议编辑区里面主
    bottom_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*4/9)
    bottom_editor.pack(side=BOTTOM, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(bottom_editor)
    
    entriesIP = create_protocol_editor(top_editor, ip_fields)
    entriesICMP = create_protocol_editor(bottom_editor, icmp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(bottom_editor)
    tk.bind('<Return>', (lambda event: send_icmp_packet(entriesIP, entriesICMP, send_packet_button)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>',(lambda event: send_icmp_packet(entriesIP, entriesICMP, send_packet_button)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_upper_protocol_editor(entriesIP,entriesICMP)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_icmp_packet(entriesIP, entriesICMP)))

def create_default_icmp_packet(entriesIP, entriesICMP):
    #在协议字段编辑框中填入默认ICMP包的字段值
    clear_protocol_editor(entriesIP)
    clear_protocol_editor(entriesICMP)
    icmp = IP(dst=default_gateway)/ICMP()
    default_icmp_packet = IP(raw(icmp))
    # 设置IP字段的值
    entriesIP[0].insert(0, default_icmp_packet.sprintf("%IP.version%"))
    entriesIP[1].insert(0, default_icmp_packet.sprintf("%IP.ihl%"))
    entriesIP[2].insert(0, default_icmp_packet.sprintf("%IP.tos%"))
    entriesIP[3].insert(0, default_icmp_packet.sprintf("%IP.len%"))
    entriesIP[4].insert(0, default_icmp_packet.sprintf("%IP.id%"))
    entriesIP[5].insert(0, 'DF')
    entriesIP[6].insert(0, default_icmp_packet.sprintf("%IP.frag%"))
    entriesIP[7].insert(0, default_icmp_packet.sprintf("%IP.ttl%"))
    entriesIP[8].insert(0, default_icmp_packet.sprintf("%IP.proto%"))
    entriesIP[9].insert(0, "点击发送按钮后自动生成首部校验和")
    entriesIP[10].insert(0, default_icmp_packet.sprintf("%IP.src%"))
    entriesIP[11].insert(0, default_gateway)
    #设置ICMP字段的值
    entriesICMP[0].insert(0, default_icmp_packet.sprintf("%r,ICMP.type%"))
    entriesICMP[1].insert(0, default_icmp_packet.sprintf("%ICMP.code%"))
    entriesICMP[2].insert(0, "点击发送按钮后自动生成校验和")
    entriesICMP[3].insert(0, default_icmp_packet.sprintf("%ICMP.id%"))
    entriesICMP[4].insert(0, default_icmp_packet.sprintf("%ICMP.seq%"))
    entriesICMP[5].insert(0, "")
  
def send_icmp_packet(entriesIP, entriesICMP, send_packet_button):
    """
    发送ICMP包
    """
    if send_packet_button['text'] == '发送':
        #封装IP数据报
        ip_version = int(entriesIP[0].get())
        ip_ihl = int(entriesIP[1].get())
        ip_tos = int(entriesIP[2].get(), 16)
        ip_len = int(entriesIP[3].get())
        ip_id = int(entriesIP[4].get(), 16)
        ip_flags = entriesIP[5].get()
        ip_frag = int(entriesIP[6].get())
        ip_ttl = int(entriesIP[7].get())
        ip_proto = entriesIP[8].get()
        ip_src = entriesIP[10].get()
        ip_dst = entriesIP[11].get()
        #封装ICMP数据报
        icmp_type = int(entriesICMP[0].get())
        icmp_code = int(entriesICMP[1].get())
        icmp_id = int(entriesICMP[3].get(), 16)
        icmp_seq = int(entriesICMP[4].get(), 16)
        icmp_data = entriesICMP[5].get()
        ip_exchange = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, flags=ip_flags,
                         frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
        icmp_exchange = ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
        # 封装好再求首部校验和
        packet_to_send = IP(raw(ip_exchange/icmp_exchange))
        ip_chksum = packet_to_send.sprintf("%IP.chksum%")
        icmp_chksum = packet_to_send.sprintf("%ICMP.chksum%")
        entriesIP[9].delete(0, END)
        entriesIP[9].insert(0, ip_chksum)
        entriesICMP[2].delete(0, END)
        entriesICMP[2].insert(0, icmp_chksum)

        t = threading.Thread(target=send_packet, args=(packet_to_send/icmp_data,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def create_ip_sender():
    """
    创建IP包编辑器
     :return: None
     """
    # IP包编辑区
    ip_fields = '版本(4 bits)：', '首部长度(4 bits)：', '区分服务(8 bits)：', '总长度(16 bits)：', '标识(16 bits)：', \
                     '标志(3 bits)：', '片偏移(13 bits)：', '生存时间(8 bits)：', '协议(8 bits)：', '首部校验和(16 bits):', \
                     '源地址(32 bits):', '目的地址(32 bits):', '自定义数据：'
    entries = create_protocol_editor(protocol_editor_panedwindow, ip_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    tk.bind('<Return>', (lambda event: send_ip_packet(entries, send_packet_button)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>',(lambda event: send_ip_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_ip_packet(entries)))

def create_default_ip_packet(entries):
        """
        在协议字段编辑框中填入默认IP包的字段值
        :param entries: 协议字段编辑框列表
        :return: None
        """
        clear_protocol_editor(entries)
        ip = IP(dst=default_gateway)
        default_ip_packet = IP(raw(ip))
        # 设置各个字段的值
        entries[0].insert(0, default_ip_packet.sprintf("%IP.version%"))
        entries[1].insert(0, default_ip_packet.sprintf("%IP.ihl%"))
        entries[2].insert(0, default_ip_packet.sprintf("%IP.tos%"))
        entries[3].insert(0, default_ip_packet.sprintf("%IP.len%"))
        entries[4].insert(0, default_ip_packet.sprintf("%IP.id%"))
        entries[5].insert(0, 'DF')
        entries[6].insert(0, default_ip_packet.sprintf("%IP.frag%"))
        entries[7].insert(0, default_ip_packet.sprintf("%IP.ttl%"))
        entries[8].insert(0, default_ip_packet.sprintf("%IP.proto%"))
        entries[9].insert(0, "点击发送按钮后自动生成首部校验和")
        entries[10].insert(0, default_ip_packet.sprintf("%IP.src%"))
        entries[11].insert(0, default_gateway)

def send_ip_packet(entries, send_packet_button):
        """
        发送IP包
        :param send_packet_button: IP包发送按钮
        :param entries:协议字段编辑框列表
        :return: None
        """
        if send_packet_button['text'] == '发送':
            ip_version = int(entries[0].get())
            ip_ihl = int(entries[1].get())
            ip_tos = int(entries[2].get(), 16)
            ip_len = int(entries[3].get())
            ip_id = int(entries[4].get(), 16)
            ip_flags = entries[5].get()
            ip_frag = int(entries[6].get())
            ip_ttl = int(entries[7].get())
            ip_proto = int(entries[8].get())
            ip_src = entries[10].get()
            ip_dst = entries[11].get()
            ip_data = entries[12].get()

            ip_exchange = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len,id=ip_id, flags=ip_flags,
                                frag=ip_frag, ttl=ip_ttl, proto=ip_proto,src = ip_src, dst=ip_dst)
            #封装好再求首部校验和
            packet_to_send = IP(raw(ip_exchange))
            ip_chksum = packet_to_send.sprintf("%IP.chksum%")
            # 清空首部校验和框，写出正确的首部校验和
            entries[9].delete(0, END)
            entries[9].insert(0, ip_chksum)
            # 开一个线程用于连续发送数据包
            t = threading.Thread(target=send_packet, args=(packet_to_send/ip_data,))
            t.setDaemon(True)
            t.start()
            # 使协议导航树不可用
            toggle_protocols_tree_state()
            send_packet_button['text'] = '停止'
        else:
            # 终止数据包发送线程
            stop_sending.set()
            # 恢复协议导航树可用
            toggle_protocols_tree_state()
            send_packet_button['text'] = '发送'

def create_tcp_sender():
    """
    创建TCP包编辑器,需要用IP包来封装
    :return: None
    """
    # TCP包编辑区,'数据负载：',
    ip_fields = '版本(4 bits)：', '首部长度(4 bits)：', '区分服务(8 bits)：', '总长度(16 bits)：', '标识(16 bits)：', \
                 '标志(3 bits)：', '片偏移(13 bits)：', '生存时间(8 bits)：', '协议(8 bits)：', '首部校验和(16 bits):', \
                 '源地址(32 bits):', '目的地址(32 bits):'
    tcp_fields = '源端口(16 bits):','目的端口(16 bits):','序号(32 bits):','确认号(32 bits):','数据偏移(4 bits):',\
                 '窗口(16 bits):','校验和(16 bits):','紧急指针(16 bits):', '自定义数据：'
    # 将IP编辑区放到协议编辑区里面主
    top_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()/2)
    top_editor.pack(side=TOP, padx=5, pady=5, expand=YES, anchor='n')
    entriesIP = create_protocol_editor(top_editor, ip_fields)
    protocol_editor_panedwindow.add(top_editor)
    # 将TCP编辑区放到协议编辑区里面主
    bottom_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()/2)
    entriesTcp = create_protocol_editor(bottom_editor, tcp_fields)

    flags_list = []
    flag_lab = Label(bottom_editor, width=20, text="TCP标志位：", anchor='e')
    FIN_var = IntVar()
    FIN_flag = Checkbutton(bottom_editor, text='FIN', variable=FIN_var)
    flags_list.append(FIN_var)
    SYN_var = IntVar()
    SYN_flag = Checkbutton(bottom_editor, text='SYN', variable=SYN_var)
    flags_list.append(SYN_var)
    RST_var = IntVar()
    RST_flag = Checkbutton(bottom_editor, text='RST', variable=RST_var)
    flags_list.append(RST_var)
    PSH_var = IntVar()
    PSH_flag = Checkbutton(bottom_editor, text='PSH', variable=PSH_var)
    flags_list.append(PSH_var)
    ACK_var = IntVar()
    ACK_flag = Checkbutton(bottom_editor, text='ACK', variable=ACK_var)
    flags_list.append(ACK_var)
    URG_var = IntVar()
    URG_flag = Checkbutton(bottom_editor, text='URG', variable=URG_var)
    flags_list.append(URG_var)
    ECE_var = IntVar()
    ECE_flag = Checkbutton(bottom_editor, text='ECE', variable=ECE_var)
    flags_list.append(ECE_var)
    CWR_var = IntVar()
    CWR_flag = Checkbutton(bottom_editor, text='CWR', variable=CWR_var)
    flags_list.append(CWR_var)
    NS_var = IntVar()
    NS_flag = Checkbutton(bottom_editor, text='NS', variable=NS_var)
    flags_list.append(NS_var)

    flag_lab.pack(side=LEFT, padx=10, pady=10)
    FIN_flag.pack(side=LEFT, after=flag_lab, padx=10)
    SYN_flag.pack(side=LEFT, after=FIN_flag, padx=10, pady=10)
    RST_flag.pack(side=LEFT, after=SYN_flag, padx=10, pady=10)
    PSH_flag.pack(side=LEFT, after=RST_flag, padx=10, pady=10)
    ACK_flag.pack(side=LEFT, after=PSH_flag, padx=10, pady=10)
    URG_flag.pack(side=LEFT, after=ACK_flag, padx=10, pady=10)
    ECE_flag.pack(side=LEFT, after=URG_flag, padx=10, pady=10)
    CWR_flag.pack(side=LEFT, after=ECE_flag, padx=10, pady=10)
    NS_flag.pack(side=LEFT, after=CWR_flag, padx=10, pady=10, expand=YES, fill=X)

    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(bottom_editor)
    bottom_editor.pack(side=BOTTOM, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(bottom_editor)

    tk.bind('<Return>', (lambda event: send_tcp_packet(entriesIP, entriesTcp, send_packet_button, flags_list)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>',
                            (lambda event: send_tcp_packet(entriesIP, entriesTcp, send_packet_button, flags_list)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_upper_protocol_editor(entriesIP, entriesTcp)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_tcp_packet(entriesIP, entriesTcp, SYN_flag, SYN_var)))

def create_default_tcp_packet(entriesIP, entriesTcp, SYN_flag, SYN_var):
    #在协议字段编辑框中填入默认TCP包的字段值
    clear_protocol_editor(entriesIP)
    clear_protocol_editor(entriesTcp)
    ip = IP(dst=default_gateway)
    tcp = TCP()
    ip_tcp = ip/tcp
    default_ip_tcp_packet = IP(raw(ip_tcp))
    # 设置IP字段的值
    entriesIP[0].insert(0, default_ip_tcp_packet.sprintf("%IP.version%"))
    entriesIP[1].insert(0, default_ip_tcp_packet.sprintf("%IP.ihl%"))
    entriesIP[2].insert(0, default_ip_tcp_packet.sprintf("%IP.tos%"))
    entriesIP[3].insert(0, default_ip_tcp_packet.sprintf("%IP.len%"))
    entriesIP[4].insert(0, default_ip_tcp_packet.sprintf("%IP.id%"))
    entriesIP[5].insert(0, 'DF')
    entriesIP[6].insert(0, default_ip_tcp_packet.sprintf("%IP.frag%"))
    entriesIP[7].insert(0, default_ip_tcp_packet.sprintf("%IP.ttl%"))
    entriesIP[8].insert(0, default_ip_tcp_packet.sprintf("%IP.proto%"))
    entriesIP[9].insert(0, "点击发送按钮后自动生成首部校验和")
    entriesIP[10].insert(0, default_ip_tcp_packet.sprintf("%IP.src%"))
    entriesIP[11].insert(0, default_gateway)
    #设置TCP字段的值
    entriesTcp[0].insert(0, default_ip_tcp_packet.sprintf("%TCP.sport%"))
    entriesTcp[1].insert(0, default_ip_tcp_packet.sprintf("%TCP.dport%"))
    entriesTcp[2].insert(0, default_ip_tcp_packet.sprintf("%TCP.seq%"))
    entriesTcp[3].insert(0, default_ip_tcp_packet.sprintf("%TCP.ack%"))
    entriesTcp[4].insert(0, default_ip_tcp_packet.sprintf("%TCP.dataofs%"))
    entriesTcp[5].insert(0, default_ip_tcp_packet.sprintf("%TCP.window%"))
    entriesTcp[6].insert(0, "点击发送按钮后自动生成校验和")
    entriesTcp[7].insert(0, default_ip_tcp_packet.sprintf("%TCP.urgptr%"))
    entriesTcp[8].insert(0, "")
    #设置标志位
    SYN_flag.config(relief=GROOVE)
    SYN_var.set(1)

def send_tcp_packet(entriesIP, entriesTcp, send_packet_button, flags_list):
    """
    发送TCP包
    """
    if send_packet_button['text'] == '发送':
        #封装IP数据报
        ip_version = int(entriesIP[0].get())
        ip_ihl = int(entriesIP[1].get())
        ip_tos = int(entriesIP[2].get(), 16)
        ip_len = int(entriesIP[3].get())
        ip_id = int(entriesIP[4].get(), 16)
        ip_flags = entriesIP[5].get()
        ip_frag = int(entriesIP[6].get())
        ip_ttl = int(entriesIP[7].get())
        ip_proto = entriesIP[8].get()
        ip_src = entriesIP[10].get()
        ip_dst = entriesIP[11].get()
        #封装TCP数据报
        tcp_sport = entriesTcp[0].get()
        tcp_dport = entriesTcp[1].get()
        tcp_seq = int(entriesTcp[2].get())
        tcp_ack = int(entriesTcp[3].get())
        tcp_dataofs = int(entriesTcp[4].get())
        tcp_window = int(entriesTcp[5].get())
        tcp_urgptr = int(entriesTcp[7].get())
        tcp_data = entriesTcp[8].get()
        #获得标志位
        tcp_flags = ['F','S','R','P','A','U','E','C','N']
        tcp_flag = ''
        for flag in flags_list:
            if flag.get():
                tcp_flag += tcp_flags[flags_list.index(flag)]
        print(tcp_flag)

        ip_exchange = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, flags=ip_flags,
                         frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
        tcp_exchange = TCP(sport=tcp_sport, dport=tcp_dport, seq=tcp_seq, ack=tcp_ack, dataofs=tcp_dataofs,
                           flags=tcp_flag, window=tcp_window, urgptr=tcp_urgptr)
        # 封装好再求首部校验和
        packet_to_send = IP(raw(ip_exchange/tcp_exchange))
        ip_chksum = packet_to_send.sprintf("%IP.chksum%")
        tcp_chksum = packet_to_send.sprintf("%TCP.chksum%")
        # 清空IP和TCP校验和框中的内容，写出正确的首部校验和
        entriesIP[9].delete(0, END)
        entriesIP[9].insert(0, ip_chksum)
        entriesTcp[6].delete(0, END)
        entriesTcp[6].insert(0, tcp_chksum)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send/tcp_data,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def create_udp_sender():
    """
    创建UDP包编辑器,需要用IP包来封装
    :return: None
    """
    # UDP包编辑区,'数据负载：',
    ip_fields = '版本(4 bits)：', '首部长度(4 bits)：', '区分服务(8 bits)：', '总长度(16 bits)：', '标识(16 bits)：', \
                 '标志(3 bits)：', '片偏移(13 bits)：', '生存时间(8 bits)：', '协议(8 bits)：', '首部校验和(16 bits):', \
                 '源地址(32 bits):', '目的地址(32 bits):'
    udp_fields = '源端口(16 bits):','目的端口(16 bits):','数据长度(16 bits):','UDP校验和(16 bits):','数据负载：'
    # 将IP编辑区放到协议编辑区里面主
    top_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*5/9)
    top_editor.pack(side=TOP, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(top_editor)
    # 将UDP编辑区放到协议编辑区里面主
    bottom_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*4/9)
    bottom_editor.pack(side=BOTTOM, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(bottom_editor)

    entriesIP = create_protocol_editor(top_editor, ip_fields)
    entriesUDP = create_protocol_editor(bottom_editor, udp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(bottom_editor)
    tk.bind('<Return>', (lambda event: send_udp_packet(entriesIP, entriesUDP, send_packet_button)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>',(lambda event: send_udp_packet(entriesIP, entriesUDP, send_packet_button)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_upper_protocol_editor(entriesIP, entriesUDP)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_udp_packet(entriesIP, entriesUDP)))

def create_default_udp_packet(entriesIP, entriesUDP):
    #在协议字段编辑框中填入默认UDP包的字段值
    clear_protocol_editor(entriesIP)
    clear_protocol_editor(entriesUDP)
    ip = IP(dst=default_gateway)
    udp = UDP()
    ip_udp = ip/udp
    default_ip_udp_packet = IP(raw(ip_udp))
    # 设置IP字段的值
    entriesIP[0].insert(0, default_ip_udp_packet.sprintf("%IP.version%"))
    entriesIP[1].insert(0, default_ip_udp_packet.sprintf("%IP.ihl%"))
    entriesIP[2].insert(0, default_ip_udp_packet.sprintf("%IP.tos%"))
    entriesIP[3].insert(0, default_ip_udp_packet.sprintf("%IP.len%"))
    entriesIP[4].insert(0, default_ip_udp_packet.sprintf("%IP.id%"))
    entriesIP[5].insert(0, 'DF')
    entriesIP[6].insert(0, default_ip_udp_packet.sprintf("%IP.frag%"))
    entriesIP[7].insert(0, default_ip_udp_packet.sprintf("%IP.ttl%"))
    entriesIP[8].insert(0, default_ip_udp_packet.sprintf("%IP.proto%"))
    entriesIP[9].insert(0, "点击发送按钮后自动生成首部校验和")
    entriesIP[10].insert(0, default_ip_udp_packet.sprintf("%IP.src%"))
    entriesIP[11].insert(0, default_gateway)
    #设置UDP字段的值
    entriesUDP[0].insert(0, default_ip_udp_packet.sprintf("%UDP.sport%"))
    entriesUDP[1].insert(0, default_ip_udp_packet.sprintf("%UDP.dport%"))
    entriesUDP[2].insert(0, default_ip_udp_packet.sprintf("%UDP.len%"))
    entriesUDP[3].insert(0, "点击发送按钮后自动生成校验和")
    entriesUDP[4].insert(0, "")

def send_udp_packet(entriesIP, entriesUDP, send_packet_button):
    """
    发送UDP包
    """
    if send_packet_button['text'] == '发送':
        #封装IP数据报
        ip_version = int(entriesIP[0].get())
        ip_ihl = int(entriesIP[1].get())
        ip_tos = int(entriesIP[2].get(), 16)
        ip_len = int(entriesIP[3].get())
        ip_id = int(entriesIP[4].get(), 16)
        ip_flags = entriesIP[5].get()
        ip_frag = int(entriesIP[6].get())
        ip_ttl = int(entriesIP[7].get())
        ip_proto = entriesIP[8].get()
        ip_src = entriesIP[10].get()
        ip_dst = entriesIP[11].get()
        #封装UDP数据报
        udp_sport = entriesUDP[0].get()
        udp_dport = entriesUDP[1].get()
        upd_len = int(entriesUDP[2].get())
        udp_data = entriesUDP[4].get()

        ip_exchange = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, flags=ip_flags,
                         frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
        tcp_exchange = UDP(sport=udp_sport, dport=udp_dport, len=upd_len)
        # 封装好再求首部校验和
        packet_to_send = IP(raw(ip_exchange/tcp_exchange))
        ip_chksum = packet_to_send.sprintf("%IP.chksum%")
        udp_chksum = packet_to_send.sprintf("%UDP.chksum%")
        # 清空IP和UDP校验和框中的内容，写出正确的首部校验和
        entriesIP[9].delete(0, END)
        entriesIP[9].insert(0, ip_chksum)
        entriesUDP[3].delete(0, END)
        entriesUDP[3].insert(0, udp_chksum)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send/udp_data,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def create_dns_sender():
    """
    创建DNS应用层数据报，其上层协议是UDP
    :return: None
    """
    ip_fields = '版本(4 bits)：', '首部长度(4 bits)：', '区分服务(8 bits)：', '总长度(16 bits)：', '标识(16 bits)：', \
                 '标志(3 bits)：', '片偏移(13 bits)：', '生存时间(8 bits)：', '协议(8 bits)：', '首部校验和(16 bits):', \
                 '源地址(32 bits):', '目的地址(32 bits):'
    udp_fields = '源端口(16 bits):','目的端口(16 bits):','数据长度(16 bits):','UDP校验和(16 bits):'
    dns_fields = '会话标识(16 bits):', 'qr(1 bits):', 'opcode(4 bits):', 'tc(1 bits):', 'rd(1 bits):', 'z(3 bits):','rcode(4 bits):',\
                 '问题数(16 bits):', '回答资源记录数(16 bits):', '授权资源记录数(16 bits):', '附加资源记录数(16 bits):'
    # 将IP编辑区放到协议编辑区里面主
    top_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*7/27)
    entriesIP = create_protocol_editor(top_editor, ip_fields)
    top_editor.pack(side=TOP, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(top_editor)
    # 将UDP编辑区放到协议编辑区里面主
    bottom_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*4/27)
    entriesUDP = create_protocol_editor(bottom_editor, udp_fields)
    bottom_editor.pack(side=BOTTOM, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(bottom_editor)
    # 放置DNS区
    dns_editor = Frame(protocol_editor_panedwindow,height=protocol_editor_panedwindow.winfo_height()*16/27)
    entriesDNS = create_protocol_editor(dns_editor, dns_fields)
    dns_editor.pack(side=BOTTOM, padx=5, pady=5, expand=YES, anchor='n')
    protocol_editor_panedwindow.add(dns_editor)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(dns_editor)
    
    tk.bind('<Return>', (lambda event: send_dns_packet(entriesIP, entriesUDP, entriesDNS, send_packet_button)))  # <Return>代表回车键
    send_packet_button.bind('<Button-1>',(lambda event: send_dns_packet(entriesIP, entriesUDP, entriesDNS, send_packet_button)))  # <Button-1>代表鼠标左键单击
    reset_button.bind('<Button-1>', (lambda event: clear_third_protocol_editor(entriesIP, entriesUDP,entriesDNS)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_dns_packet(entriesIP, entriesUDP, entriesDNS)))

def create_default_dns_packet(entriesIP, entriesUDP, entriesDNS):
    #在协议字段编辑框中填入默认UDP包的字段值
    clear_protocol_editor(entriesIP)
    clear_protocol_editor(entriesUDP)
    ip = IP(dst=default_gateway)
    udp = UDP()
    dns = DNS()
    default_dns_packet = IP(raw(ip/udp/dns))
    # 设置IP字段的值
    entriesIP[0].insert(0, default_dns_packet.sprintf("%IP.version%"))
    entriesIP[1].insert(0, default_dns_packet.sprintf("%IP.ihl%"))
    entriesIP[2].insert(0, default_dns_packet.sprintf("%IP.tos%"))
    entriesIP[3].insert(0, default_dns_packet.sprintf("%IP.len%"))
    entriesIP[4].insert(0, default_dns_packet.sprintf("%IP.id%"))
    entriesIP[5].insert(0, 'DF')
    entriesIP[6].insert(0, default_dns_packet.sprintf("%IP.frag%"))
    entriesIP[7].insert(0, default_dns_packet.sprintf("%IP.ttl%"))
    entriesIP[8].insert(0, default_dns_packet.sprintf("%IP.proto%"))
    entriesIP[9].insert(0, "点击发送按钮后自动生成首部校验和")
    entriesIP[10].insert(0, default_dns_packet.sprintf("%IP.src%"))
    entriesIP[11].insert(0, default_gateway)
    #设置UDP字段的值
    entriesUDP[0].insert(0, default_dns_packet.sprintf("%UDP.sport%"))
    entriesUDP[1].insert(0, default_dns_packet.sprintf("%UDP.dport%"))
    entriesUDP[2].insert(0, default_dns_packet.sprintf("%UDP.len%"))
    entriesUDP[3].insert(0, "点击发送按钮后自动生成校验和")
    #设置DNS字段,将DNS中的flags标志位的值整合在一起
    entriesDNS[0].insert(0,default_dns_packet.sprintf("%r,DNS.id%"))
    entriesDNS[1].insert(0, default_dns_packet.sprintf("%r,DNS.qr%"))
    entriesDNS[2].insert(0, default_dns_packet.sprintf("%r,DNS.opcode%"))
    entriesDNS[3].insert(0, default_dns_packet.sprintf("%r,DNS.tc%"))
    entriesDNS[4].insert(0, default_dns_packet.sprintf("%r,DNS.rd%"))
    entriesDNS[5].insert(0, default_dns_packet.sprintf("%r,DNS.z%"))
    entriesDNS[6].insert(0, default_dns_packet.sprintf("%r,DNS.rcode%"))
    entriesDNS[7].insert(0, default_dns_packet.sprintf("%DNS.qdcount%"))
    entriesDNS[8].insert(0, default_dns_packet.sprintf("%DNS.ancount%"))
    entriesDNS[9].insert(0, default_dns_packet.sprintf("%DNS.nscount%"))
    entriesDNS[10].insert(0, default_dns_packet.sprintf("%DNS.arcount%"))
    

def send_dns_packet(entriesIP, entriesUDP, entriesDNS, send_packet_button):
    """
    发送应用层的DNS包
    """
    if send_packet_button['text'] == '发送':
        #封装IP数据报
        ip_version = int(entriesIP[0].get())
        ip_ihl = int(entriesIP[1].get())
        ip_tos = int(entriesIP[2].get(), 16)
        ip_len = int(entriesIP[3].get())
        ip_id = int(entriesIP[4].get(), 16)
        ip_flags = entriesIP[5].get()
        ip_frag = int(entriesIP[6].get())
        ip_ttl = int(entriesIP[7].get())
        ip_proto = entriesIP[8].get()
        ip_src = entriesIP[10].get()
        ip_dst = entriesIP[11].get()
        #封装UDP数据报
        udp_sport = entriesUDP[0].get()
        udp_dport = entriesUDP[1].get()
        upd_len = int(entriesUDP[2].get())
        #封装DNS包
        dns_id = int(entriesDNS[0].get(),16)
        dns_qr = int(entriesDNS[1].get())
        dns_opcode = int(entriesDNS[2].get(), 16)
        dns_tc = int(entriesDNS[3].get())
        dns_rd = int(entriesDNS[4].get())
        dns_z = int(entriesDNS[5].get(), 16)
        dns_rcode = int(entriesDNS[6].get(), 16)
        dns_qdcount = int(entriesDNS[7].get())
        dns_ancount = int(entriesDNS[8].get())
        dns_nscount = int(entriesDNS[9].get())
        dns_arcount = int(entriesDNS[10].get())

        ip_exchange = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, flags=ip_flags,
                         frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
        tcp_exchange = UDP(sport=udp_sport, dport=udp_dport, len=upd_len)
        dns = DNS(id=dns_id, qr=dns_qr, opcode=dns_opcode, tc=dns_tc, rd=dns_rd, z=dns_z, rcode=dns_rcode, qdcount=dns_qdcount, ancount=dns_ancount, nscount=dns_nscount, arcount=dns_arcount)
        # 封装好再求首部校验和
        packet_to_send = IP(raw(ip_exchange/tcp_exchange/dns))
        ip_chksum = packet_to_send.sprintf("%IP.chksum%")
        udp_chksum = packet_to_send.sprintf("%UDP.chksum%")
        # 清空IP和UDP校验和框中的内容，写出正确的首部校验和
        entriesIP[9].delete(0, END)
        entriesIP[9].insert(0, ip_chksum)
        entriesUDP[3].delete(0, END)
        entriesUDP[3].insert(0, udp_chksum)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'

def send_packet(packet_to_send):
    """
    用于发送数据包的线程函数，持续发送数据包
    :type packet_to_send: 待发送的数据包
    """
    # print(packet.show(dump=True))
    # 对发送的数据包次数进行计数，用于计算发送速度
    n = 0
    stop_sending.clear()
    # 待发送数据包的长度（用于计算发送速度）
    packet_size = len(packet_to_send)
   # print(packet_to_send.show())
    # 推导数据包的协议类型
    proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'Unknown']
    packet_proto = ''
    for pn in proto_names:
        if pn in packet_to_send:
            packet_proto = pn
            break
    # 开始发送时间点
    begin_time = datetime.now()
    while not stop_sending.is_set():
        if isinstance(packet_to_send, Ether):
            sendp(packet_to_send, verbose=0)  # verbose=0,不在控制回显'Sent 1 packets'.
        else:
            send(packet_to_send, verbose=0)
        n += 1
        end_time = datetime.now()
        total_time = (end_time - begin_time).total_seconds()
        if total_time == 0:
            total_time = 2.23E-308    # 当begin_time和end_time相等时，将total_time设为IEEE 745标准中规定的最小浮点数
        total_bytes = packet_size * n
        bytes_per_second = total_bytes / total_time / 1024
        status_bar.set('已经发送了%d个%s数据包, 已经发送了%d个字节，发送速率: %0.2fK字节/秒',
                       n, packet_proto, total_bytes, bytes_per_second)

def create_welcome_page(root):
    welcome_string = '计算机网络课程设计\n协议编辑器\n学号：150342208\n姓名：龚建鹏'
    Label(root, justify=CENTER, padx=10, pady=150, text=welcome_string,
          font=('隶书', '30', 'bold')).pack()

if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建欢迎界面
    create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)
    # 启动消息处理
    tk.mainloop()
