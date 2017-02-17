import time
from idc import *
from idaapi import *
from idautils import *


class DbgHook(DBG_Hooks):
    def __init__(self):
        DBG_Hooks.__init__(self)

    def __logToFile__(self, action, text):
        f = open('ssllog.txt', 'a')
        f.write('\n[%s] %s => %s\n' % (time.ctime(), action, text))
        f.close()

    def __hooker__(self, ea):
        stack = cpu.Ebp if cpu.Ebp < cpu.Esp else cpu.Esp
        Message("Stack %0.8X\n" % stack)
        funcName = GetDisasm(ea)
        if 'SSL_write' in funcName:
            text = GetManyBytes(cpu.Ebx, cpu.Eax, True)
            self.__logToFile__('Write', text)
        else:
            # msg = GetManyBytes(stack + 4, 4)
            # Message("Stack+4 " + str(msg) + "\n")
            # if msg:
            #    msg = msg[::-1].encode('hex')
            #    StepOver()
            #    text = GetString(int(msg, 16))
            text = GetManyBytes(cpu.Ebx, cpu.Eax, True)
            self.__logToFile__('Read', text)
        continue_process()

    def dbg_bpt(self, tid, ea):
        self.__hooker__(ea)
        return 0


debugger = DbgHook()
debugger.hook()

ssl_func = ['SSL_write', 'SSL_read']

current_addr = ScreenEA()
# Find all ssl function and set breakpoint
for function in Functions(SegStart(current_addr), SegEnd(current_addr)):
    funcName = GetFunctionName(function)
    if funcName in ssl_func:
        for xref in CodeRefsTo(function, 0):
            if funcName == 'SSL_write':
                AddBpt(xref)
            else:
                xref += 5
                AddBpt(xref)
            # SetBptAttr(xref, BPTATTR_FLAGS, 0x0)
