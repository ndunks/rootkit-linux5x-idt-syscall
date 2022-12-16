alias ss=target remote :1234
file /rifin/app/linux-5.6.3/vmlinux
#file vmlinux
b start_kernel
b entry_INT80_compat
b do_int80_syscall_32
ss
