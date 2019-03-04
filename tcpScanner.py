from tkinter.filedialog import *
from tkinter.font import Font

from scapy.layers.inet import *
from scapy.sendrecv import sr


class Edit_save(object):
    def __init__(self):
        self.root = Tk()
        self.root.title('TCP扫描器')
        self.root.geometry('+120+50')
        self.root.minsize(width='750', height='150')
        self.font_en = Font(self.root, size=12)
        self.font_text = Font(self.root, family="Helvetica", size=12, weight='bold')
        
        self.fm_base = Frame(self.root)
        self.fm_up = Frame(self.fm_base)
        
        self.label_dst = Label(self.fm_up, font=self.font_en, width=10, text="目的地址：")
        self.var_dst = StringVar()
        self.en_dst = Entry(self.fm_up, textvariable=self.var_dst, width=50)
        self.label_dst.pack(side=LEFT, expand=YES)
        self.en_dst.pack(side=LEFT, after=self.label_dst)
        
        self.label_port = Label(self.fm_up,  font=self.font_en, width=10, text="扫描端口：")
        self.var_port = StringVar()
        self.en_port = Entry(self.fm_up, textvariable=self.var_port, width=50)
        self.label_port.pack(side=LEFT, after=self.en_dst, padx=20, pady=10, expand=YES)
        self.en_port.pack(side=LEFT, after=self.label_port)
        
        self.bt_open = Button(self.fm_up, text='开始扫描', bg='green')
        self.bt_open.pack(side=LEFT, after=self.en_port, padx=10, pady=10)
        self.bt_open.config(command=self.__scanner)

        self.fm_up.pack(fill=X)
        self.fm_base.pack(fill=X)
        self.fm_down = Frame(self.root)
        self.text = Text(self.fm_down, font=self.font_text)
        self.text.pack(side=LEFT, fill=BOTH, expand=True)
        self.scb = Scrollbar(self.fm_down)
        self.scb.pack(side=LEFT, fill=Y)
        self.text.config(yscrollcommand=self.scb.set)
        self.scb.config(command=self.text.yview)
        self.fm_down.pack(fill=BOTH, expand=True)
        self.root.mainloop()
    
    def __scanner(self):
        self.dst = self.en_dst.get()
        self.port = self.en_port.get()
        print('dst:' + self.dst)
        print('port:' + self.port)
        list_dst = []
        list_port = []
        lines_dst = self.dst.split('/')
        lines_port = self.port.split(',')
        for item in lines_dst:
            list_dst.append(item)
        for item in lines_port:
            list_port.append(item)
        print(len(list_dst))
        print(len(list_port))
        if self.port == '':    #说明是路由追踪
            ans, unans = sr(IP(dst=list_dst, ttl=(4, 25), id=RandShort()) / TCP(flags=0x2),timeout=10)
            for snd, rcv in ans:
                text = snd.ttl + rcv.src + isinstance(rcv.payload, TCP)
                print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))
        else:
            self.ans, unans = sr(IP(dst=list_dst) / TCP(sport=RandShort(), dport=list_port, flags="S"),timeout=10)
            self.ans.make_table(
                lambda p: (p[0][IP].dst, p[0][TCP].dport, p[1].sprintf("{TCP:%TCP.flags%}{ICMP:%ICMP.type%}")))

        self.text.delete('1.0', END)
        self.text.insert('1.0', text)
   
if __name__ == "__main__":
    Edit_save()