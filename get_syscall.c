#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

// https://github.com/linsec/hook-syscall

/*
Getting linux syscall table from IDT
Kernel: Linux 5.6.3 x86_64
*/

typedef void (*sys_call_ptr_t)(void);

static sys_call_ptr_t *sys_call_table = NULL;

static int find_syscall_table64_test(void)
{
    pr_info("Finding sys_call_table 64 BIT..\n");
    struct desc_ptr idtr;
    gate_desc *idt_table, *system_call_gate;
    // interupt vector (syscall / int 0x80) handler offset & pointer
    unsigned char *entry_INT80;
    unsigned char *_system_call_ptr;
    unsigned char *do_int80_syscall;
    unsigned long offset;
    int i;
    u_char *off;

    // Get CPU IDT table
    asm("sidt %0"
        : "=m"(idtr));

    pr_info("IDT address %px  %u\n", idtr.address, idtr.size);
    // IDT address fffffe0000000000  4095

    if (idtr.size == 0 || idtr.address == 0)
    {
        pr_err("Can't get idtr value");
        return -1;
    }

    // set table pointer
    idt_table = (gate_desc *)idtr.address;

    // set gate_desc for int 0x80
    system_call_gate = &idt_table[0x80];

    // get int 0x80 handler offset
    entry_INT80 = gate_offset(system_call_gate);
    // entry_INT80 = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
    // _system_call_ptr = (unsigned char *)entry_INT80;

    pr_info("Syscall Gates %px\n", entry_INT80);

    // Syscall Gates ffffffff816012b0 / entry_INT80_compat

    // Locate the sys_call_table address
    // Code in https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/entry_64_compat.S#L342

    // entry_INT80_compat: 0xffffffff81002f21

    pr_info("finding call OPCODE..\n", entry_INT80);
    for (i = 0; i < 256; i++)
    {
        entry_INT80++;
        if (*(entry_INT80) == 0xe8)
        {
            // e8 fe 04 60 ff  call   0xffffffff81001bb0 <do_int80_syscall_32>
            pr_info("Found at (%i) %px : %02x %02x %02x %02x %02x\n", i,
                    entry_INT80, *(entry_INT80), *(entry_INT80 + 1), *(entry_INT80 + 2), *(entry_INT80 + 3), *(entry_INT80 + 4));
            // 32 bit adress in x64 system
            offset = *(entry_INT80 + 1) |
                     (*(entry_INT80 + 2) << 8) |
                     (*(entry_INT80 + 3) << 16) |
                     (*(entry_INT80 + 4) << 24);
            // Adjust for $RIP of 5 byte (1 instruction )
            entry_INT80 += 5;
            do_int80_syscall = entry_INT80 + offset;
            pr_info("do_int80_syscall offset %08x at %px\n", offset, do_int80_syscall);
            break;
        }
    }
    if (do_int80_syscall == NULL)
    {
        pr_err("Unable to locate do_int80_syscall\n");
        return -1;
    }
    // Direct call from sys_call_table
    for (i = 0; i < 256; i++)
    {
        do_int80_syscall++;
        // ff 14 c5 a0 11 a0 81   call   *-0x7e5fee60(,%rax,8)
        if (*(do_int80_syscall) == 0xff &&
            *(do_int80_syscall + 1) == 0x14 &&
            *(do_int80_syscall + 2) == 0xc5)
        {
            // syscall address is here
            do_int80_syscall += 3;
            sys_call_table = (0xffffffff00000000U) | *((u32 *)do_int80_syscall);
            return 0;
        }
    }

    if( sys_call_table != NULL ){
        // Found through call pattern
        return 0;
    }
    // Finding array access to sys_call_table
    pr_info("Finding sys_call_table array access\n");
    for (i = 0; i < 256; i++)
    {
        do_int80_syscall++;
        // 48 8b 04 c5 a0 11 e0 81 mov    -0x7e1fee60(,%rax,8),%rax
        if (*(do_int80_syscall) == 0x48 &&
            *(do_int80_syscall + 1) == 0x8b &&
            *(do_int80_syscall + 2) == 0x04 &&
            *(do_int80_syscall + 3) == 0xc5)
        {
            // syscall address is here
            do_int80_syscall += 4;

            sys_call_table = (0xffffffff00000000U) | *((u32 *)do_int80_syscall);
            return 0;
        }
    }
    return -1;
}

// https://github.com/reveng007/reveng_rtkit
typedef unsigned long (*kallsyms_lookup_name_func)(const char *name);
int lookup_syscall_table(void)
{
    pr_info("Looking up sys_call_table..");
    if (kallsyms_lookup_name == NULL)
    {
        struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"};
        kallsyms_lookup_name_func lookup_name;
        register_kprobe(&kp);
        if (kp.addr == NULL)
        {
            pr_err("Probe failed\n");
            return -1;
        }
        lookup_name = (void *)kp.addr;
        printk("kallsyms_lookup_name %px", kp.addr);
        unregister_kprobe(&kp);
        sys_call_table = lookup_name("sys_call_table");
    }
    else
    {
        sys_call_table = kallsyms_lookup_name("sys_call_table");
    }
    return sys_call_table == NULL;
}

// static int prsyms_print_symbol(void *data, const char *namebuf,
//                                struct module *module, unsigned long address)
// {
//     pr_info("### %lx\t%s\n", address, namebuf);
//     return 0;
// }

static int main_init(void)
{
    // if (lookup_syscall_table())
    // {
    // try by byte searching opcode
    if (find_syscall_table64_test())
    {
        // Show all available symbols
        // kallsyms_on_each_symbol(prsyms_print_symbol, NULL);
    }
    //}

    if (sys_call_table == NULL)
    {
        pr_err("Cannot find sys_call_table\n");
        return -1;
    }
    // pr_info("Current EIP:  %px\n", __builtin_return_address(1));
    pr_info("Found sys_call_table: %px\n", sys_call_table);
    return 0;
}
// [    5.734572] sprint_symbol = ffffffff81093f28
// [    7.093615] F1:  0000000000000000
// [    7.093842] sprint_symbol = ffffffff81093f28
// [    8.415684] F2:  0000000000000000
// [    8.415883] sprint_symbol = ffffffff81093f28

static void main_exit(void)
{
    // modify_sys_call_ioctl(org_ioctl);
    pr_info("Exit..\n");
    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xxx");
MODULE_DESCRIPTION("Sample.");
MODULE_VERSION("0.01");