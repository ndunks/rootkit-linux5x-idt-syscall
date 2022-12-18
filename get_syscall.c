#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include "get_syscall.h"

typedef void (*fun)(void);
/** x64 sys_call_table: https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/syscalls/syscall_64.tbl */
static fun *sys_call_table;
/** x32 sys_call_table: https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/syscalls/syscall_32.tbl */
static fun *ia32_sys_call_table;

// 64 bit kernel that support Binary Emulations
// CONFIG_IA32_EMULATION=y
static int find_syscall_table64_ia32(void)
{
    struct desc_ptr idtr;
    gate_desc *idt_table, *system_call_gate;
    unsigned char *entry_INT80 = NULL;
    unsigned char *do_int80_syscall = NULL;
    unsigned long offset;
    int i;
    u_char *off;

    pr_info("Finding sys_call_table x86_64 IA32..\n");
    // Get CPU IDT table
    asm("sidt %0"
        : "=m"(idtr));

    pr_info("IDT address %px  %u\n", (void *)idtr.address, idtr.size);
    // IDT address fffffe0000000000  4095

    if (idtr.size == 0 || idtr.address == 0)
    {
        pr_err("Can't get idtr value");
        return -1;
    }

    // set table pointer
    idt_table = (void *)idtr.address;

    // set gate_desc for int 0x80
    system_call_gate = &idt_table[0x80];

    // get int 0x80 handler offset
    entry_INT80 = (void *)gate_offset(system_call_gate);
    // entry_INT80 = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
    // _system_call_ptr = (unsigned char *)entry_INT80;

    pr_info("Syscall Gates %px\n", entry_INT80);

    // Syscall Gates ffffffff816012b0 / entry_INT80_compat

    // Locate the sys_call_table address
    // Code in https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/entry_64_compat.S#L342

    // entry_INT80_compat: 0xffffffff81002f21

    pr_info("finding call OPCODE..\n");
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
            pr_info("do_int80_syscall offset %08lx at %px\n", offset, do_int80_syscall);
            break;
        }
    }
    if (do_int80_syscall == NULL)
    {
        pr_err("Unable to locate do_int80_syscall\n");
        return -1;
    }

    off = do_int80_syscall;
    // Direct call from sys_call_table
    pr_info("finding direct call from sys_call_table\n");
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
            ia32_sys_call_table = (void *)((0xffffffff00000000U) | *((u32 *)do_int80_syscall));
            return 0;
        }
    }

    if (ia32_sys_call_table != NULL)
    {
        // Found through call pattern
        return 0;
    }
    do_int80_syscall = off;
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
            pr_info("Found at (%i) %px : %02x %02x %02x %02x\n", i,
                    do_int80_syscall, *(do_int80_syscall), *(do_int80_syscall + 1), *(do_int80_syscall + 2), *(do_int80_syscall + 3));

            ia32_sys_call_table = (void *)((0xffffffff00000000U) | *((u32 *)do_int80_syscall));
            return 0;
        }
    }
    return -1;
}

// Using 32 Bit syscall, because the kernel is compiled with IA32 FLAG. and I targeting IT
// https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/entry/syscalls/syscall_32.tbl
// 1	i386	exit			sys_exit			__ia32_sys_exit
// 5	i386	open			sys_open			__ia32_compat_sys_open
// 54	i386	ioctl			sys_ioctl			__ia32_compat_sys_ioctl
// 16	64	ioctl			__x64_sys_ioctl
#define target_syscall32 54
#define target_syscall64 16
#define HDIO_GET_IDENTITY	0x030d	/* get IDE identification info */

typedef asmlinkage long (*syscall_fun_t)(struct pt_regs *pt_regs);
static syscall_fun_t original32, original64;
static struct hd_driveid *hd;
// maks 40
static char * fakeModel = "ASDFG";
// maks 20
static char * fakeSerial = "10101010101010xxx";
asmlinkage long fake_syscall32(struct pt_regs *pt_regs)
{
    int ret = original32(pt_regs);
    if( pt_regs->cx == HDIO_GET_IDENTITY ){
        // https://www.kernel.org/doc/Documentation/printk-formats.txt
        printk("Hooked ioctl32 ( %lx, %lx, %px )\n", pt_regs->bx, pt_regs->cx, pt_regs->dx);
        hd = (void *) pt_regs->dx;
        // LEN + 1
        memcpy(&(hd->model), fakeModel, 6);
        memcpy(&(hd->serial_no), fakeSerial, 18);
    }
    return ret;
}

asmlinkage long fake_syscall64(struct pt_regs *pt_regs)
{
    int ret = original64(pt_regs);
    if( pt_regs->si == HDIO_GET_IDENTITY ){
        // https://www.kernel.org/doc/Documentation/printk-formats.txt
        printk("Hooked ioctl64 ( %lx, %lx, %px )\n", pt_regs->di, pt_regs->si, pt_regs->dx);
        hd = (void *) pt_regs->dx;
        // LEN + 1
        memcpy(&(hd->model), fakeModel, 6);
        memcpy(&(hd->serial_no), fakeSerial, 18);
    }
    return ret;
}

static int override_syscall(void)
{
    unsigned int level;
    pte_t *pte;
    original32 = (syscall_fun_t)ia32_sys_call_table[target_syscall32];
    pr_info("ORIGINAL32 %i : %px\n", target_syscall32, original32);
    pr_info("FAKE32     %i : %px\n", target_syscall32, fake_syscall32);
    original64 = (syscall_fun_t)sys_call_table[target_syscall64];
    pr_info("ORIGINAL64 %i : %px\n", target_syscall64, original64);
    pr_info("FAKE64     %i : %px\n", target_syscall64, fake_syscall64);

    pte = lookup_address((unsigned long)ia32_sys_call_table, &level);
    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));
    ia32_sys_call_table[target_syscall32] = (void *)fake_syscall32;
    // reprotect page
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    pte = lookup_address((unsigned long)sys_call_table, &level);
    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));
    sys_call_table[target_syscall64] = (void *)fake_syscall64;
    // reprotect page
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    pr_info("override_syscall done");
    return 0;
}

static int restore_syscall(void)
{
    unsigned int level;
    pte_t *pte;
    pte = lookup_address((unsigned long)ia32_sys_call_table, &level);
    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));
    ia32_sys_call_table[target_syscall32] = (fun)original32;
    // reprotect page
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    pte = lookup_address((unsigned long)sys_call_table, &level);
    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));
    sys_call_table[target_syscall64] = (fun)original64;
    // reprotect page
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    return 0;
}

static int main_init(void)
{
    if (find_syscall_table64_ia32())
    {
        // Show all available symbols
        // kallsyms_on_each_symbol(prsyms_print_symbol, NULL);
    }

    if (ia32_sys_call_table == NULL)
    {
        pr_err("Cannot find sys_call_table\n");
        return -1;
    }
    sys_call_table = (void *)((unsigned long) ia32_sys_call_table - 4032lu);

    pr_info("Found ia32_sys_call_table: %px\n", ia32_sys_call_table);
    pr_info("Found sys_call_table: %px\n", sys_call_table);

    return override_syscall();
    return 0;
}

static void main_exit(void)
{
    if (original32 != NULL)
    {
        pr_info("Restoring hook..\n");
        restore_syscall();
    }
    pr_info("Exit..\n");
    return;
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xxx");
MODULE_DESCRIPTION("Sample.");
MODULE_VERSION("0.01");