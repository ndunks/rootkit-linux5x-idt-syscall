#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <linux/device.h>
#include <linux/of_platform.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>
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
#define HDIO_GET_IDENTITY 0x030d /* get IDE identification info */

// https://elixir.bootlin.com/linux/v5.6.3/source/include/scsi/sg.h#L209

typedef asmlinkage long (*syscall_fun_t)(struct pt_regs *pt_regs);
static syscall_fun_t original32, original64;
static struct hd_driveid *hd;
static struct sg_io_hdr *sg;
// maks 40
static char *fakeModel = "ASDFGHJK                                ";
// maks 20
static char *fakeSerial = "XYZ-SERIAL          ";
asmlinkage long fake_syscall32(struct pt_regs *pt_regs)
{
    int ret = original32(pt_regs);

    if (pt_regs->cx == HDIO_GET_IDENTITY)
    {
        // https://www.kernel.org/doc/Documentation/printk-formats.txt
        printk("ioctl32 HDIO_GET_IDENTITY ( %lx, %lx, %px )\n", pt_regs->bx, pt_regs->cx, pt_regs->dx);
        hd = (void *)pt_regs->dx;
        // LEN + 1
        memcpy(&(hd->model), fakeModel, 40);
        memcpy(&(hd->serial_no), fakeSerial, 20);
        return ret;
    }
    return ret;
}
asmlinkage int sg_ata_get_chars(const u_int16_t *word_arr, int start_word,
                                int num_words, int is_big_endian, char *ochars)
{
    int k;
    u_int16_t s;
    char a, b;
    char *op = ochars;

    for (k = start_word; k < (start_word + num_words); ++k)
    {
        s = word_arr[k];
        if (is_big_endian)
        {
            a = s & 0xff;
            b = (s >> 8) & 0xff;
        }
        else
        {
            a = (s >> 8) & 0xff;
            b = s & 0xff;
        }
        if (a == 0)
            break;
        *op++ = a;
        if (b == 0)
            break;
        *op++ = b;
    }
    return op - ochars;
}
asmlinkage int sg_ata_put_chars(const u_int16_t *word_arr, int start_word,
                                int num_words, int is_big_endian, char *ichars)
{
    u_int16_t s;
    char a, b;
    int k = 0;
    u_int16_t *op = word_arr + start_word;

    while (k < (num_words * 2))
    {
        a = ichars[k++];
        b = ichars[k++];
        if (is_big_endian)
        {
            *op = (b << 8) | a;
        }
        else
        {
            *op = (a << 8) | b;
        }
        op++;
        if (a == 0 || b == 0)
            break;
    }
    return (op - (word_arr + start_word + num_words));
}

asmlinkage long fake_syscall64(struct pt_regs *pt_regs)
{
    int ret = original64(pt_regs);
    if (pt_regs->si == HDIO_GET_IDENTITY)
    {
        // https://www.kernel.org/doc/Documentation/printk-formats.txt
        printk("ioctl64 HDIO_GET_IDENTITY ( %lx )\n", pt_regs->di);
        hd = (void *)pt_regs->dx;
        // LEN + 1
        memcpy(&(hd->model), fakeModel, 40);
        memcpy(&(hd->serial_no), fakeSerial, 20);
    }
    else if (pt_regs->si == SG_IO)
    {
        sg = (void *)pt_regs->dx;
        char *buf = sg->dxferp;
        printk("ioctl64 SG_IO cmd: 0x%x 0x%x 0x%x 0x%x\n", sg->cmdp[0], sg->cmdp[1], sg->cmdp[2], sg->cmdp[3]);
        // https://elixir.bootlin.com/linux/v5.6.3/source/include/scsi/scsi_proto.h#L32
        // https://github.com/hreinecke/sg3_utils/blob/master/src/sg_vpd.c
        // https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf
        if (sg->cmdp[0] == 0x12) // OP CODE 0x12h = inquiry
        {
            int evpd = sg->cmdp[2] & 0b10000000;
            switch (sg->cmdp[2])
            {
            case 0x80:      // Unit serial number
                if (buf[3]) // len
                {
                    buf[3] = (char)20;
                    memcpy(&(buf[4]), fakeSerial, 20);
                }
                break;

            case 0x83: // VPD_DEVICE_ID

                break;
            case 0x89: // VPD_ATA_INFO
                if (sg->dxfer_len >= 36)
                {
                }

                break;
            }
            printk("ioctl64 SG_IO 0x12 ( %lx, 0x%x 0x%x ) %i\n%*pEhp\n", pt_regs->di, sg->cmdp[0], sg->cmdp[2], sg->dxfer_len, sg->dxfer_len, sg->dxferp);
        }
        else if (sg->cmdp[0] == 0x85)
        {
            struct scsi_vpd *vpd = (void *)sg->dxferp;
            if (sg->cmdp[2] == 0xe)
            { // ATA INFO
                int cc;
                char tmp[80];
                const char *cp;
                cc = sg_ata_get_chars((const unsigned short *)buf, 27, 20, 0, tmp);
                tmp[cc] = '\0';
                printk("SG_IO 0x85 MODEL  %s\n", tmp);
                cc = sg_ata_get_chars((const unsigned short *)buf, 10, 10, 0, tmp);
                tmp[cc] = '\0';
                printk("SG_IO 0x85 SERIAL %s\n", tmp);
                cc = sg_ata_get_chars((const unsigned short *)buf, 23, 4, 0, tmp);
                tmp[cc] = '\0';
                printk("SG_IO 0x85 FIRMRV %s\n", tmp);
                // Fake it
                sg_ata_put_chars((const unsigned short *)buf, 27, 20, 0, fakeModel);
                sg_ata_put_chars((const unsigned short *)buf, 10, 10, 0, fakeSerial);
                // int len = buf[3];
                // if (len)
                // {
                //     buf[3] = (char)20;
                //     memcpy(&(buf[4]), fakeSerial, 20);
                // }
            }
            printk("SG_IO 0x85 %c, 0x%x 0x%x : %i\n%*pEhp\n", vpd->data[0], sg->cmdp[0], sg->cmdp[2], sg->dxfer_len, sg->dxfer_len, sg->dxferp);
        }
        // LEN + 1
        // memcpy(&(hd->model), fakeModel, 6);
        // memcpy(&(hd->serial_no), fakeSerial, 20);
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

// VPD PAGE 0x83
int fake_dev_ids(u_int8_t *buf, int buf_len)
{
    int off, desig_type, i_len;
    const u_int8_t *bp;
    const u_int8_t *ip;
    const char oriSn[21];
    off = -1;
    while ((off + 3) < buf_len)
    {
        if (off < 0)
        {
            off = 0;
        }
        else
        {
            off = (off + buf[off + 3] + 4);
        }
        if ((off + 4) > buf_len)
        {
            break;
        }
        bp = buf + off;
        i_len = bp[3];
        ip = bp + 4;
        desig_type = (bp[1] & 0xf);
        printk("desig_type %d, len %d, %s 8pEhp \n", desig_type, i_len, ip);
        if (desig_type == 0 && i_len == 20)
        {
            // fake serial
            printk("0x83 Serial ori: %.*s\n", i_len, ip);
            memcpy(oriSn, ip, i_len);
            memcpy(ip, fakeSerial, i_len);
            // return 0;
        }
        else if (desig_type == 1 && i_len > 20)
        {
            // check for last 20 byte is SN, fake it too
            if (strncmp(ip + i_len - 20, oriSn, 20) == 0)
            {
                memcpy(ip + i_len - 20, fakeSerial, i_len);
            }
        }
    }
    // printk("0x83 NOT FOUND\n");
    return 0;
}

static int fake_atta_info(char *buf, int len)
{
    int cc;
    char tmp[80];

    if (buf[56] == 0)
    {
        printk("No atta data found\n");
        return -1;
    }
    sg_ata_put_chars((const unsigned short *)(buf + 60), 27, 20, 0, fakeModel);
    sg_ata_put_chars((const unsigned short *)(buf + 60), 10, 10, 0, fakeSerial);
    cc = sg_ata_get_chars((const unsigned short *)(buf + 60), 27, 20,
                          0, tmp);
    tmp[cc] = '\0';
    printk("    model: %s\n", tmp);
    cc = sg_ata_get_chars((const unsigned short *)(buf + 60), 10, 10,
                          0, tmp);
    tmp[cc] = '\0';
    printk("    serial number: %s\n", tmp);
    return 0;
}
// https://elixir.bootlin.com/linux/v5.6.3/source/drivers/scsi/scsi_sysfs.c#L512
static int override_sysfs(void)
{
    struct path root_path;
    struct kstat root_stat;
    struct block_device *root_device;
    struct device *dev, *dev2;
    struct scsi_device *sdev;
    // struct scsi_disk *sdisk;
    struct scsi_vpd *vpd_buf;
    const int vpd_len = 64;
    unsigned char *buf;

    if (kern_path("/rootfs", 0, &root_path) < 0)
    {
        printk("Fail get root path\n");
        return -1;
    }
    vfs_getattr(&root_path, &root_stat, STATX_ALL, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);
    pr_info("root device number is 0x%08x; major = %d, minor = %d\n", root_stat.dev, MAJOR(root_stat.dev), MINOR(root_stat.dev));

    root_device = bdget(root_stat.dev);
    if (root_device)
    {
        dev = part_to_dev(root_device->bd_part);
        printk("Root /dev/%s\n", dev_name(dev));
        // dev2 = get_device(dev->parent);
        // printk("Root SCSI %s %s\n", dev->parent->type->name, dev->class->name);
        //  sdisk = to_scsi_disk(dev);

        sdev = to_scsi_device(dev->parent);
        printk("Root SCSI Disk %s, %s\n", dev->parent->type->name, sdev->model);
        // printk("Root SCSI %px %8pEhp\n", sdev->vpd_pg80, sdev->vpd_pg80);
        //  sdev = (void *)root_device;

        if (scsi_device_supports_vpd(sdev))
        {

            // faking 0x80
            memcpy(sdev->vpd_pg80->data + 4, fakeSerial, 20);
            printk("Root VPD %s\n", sdev->vpd_pg80->data + 4);

            // faking 0x83
            fake_dev_ids(sdev->vpd_pg83->data + 4, sdev->vpd_pg83->len - 4);

            // fakinf 0x89
            fake_atta_info(sdev->vpd_pg89->data, sdev->vpd_pg89->len);
            

            buf = kmalloc(vpd_len, GFP_KERNEL);
            if (scsi_get_vpd_page(sdev, 0x80, buf, vpd_len) == 0)
            {
                printk("Root SCSI %8pEhp\n", buf + 4);
            }
            else
            {
                printk("Can't get vpd buf\n");
            }
            kfree(buf);
        }
        else
        {
            printk("Not support SCSI Page\n");
        }
        // put_device(dev2);
        bdput(root_device);
    }
    else
    {
        printk("Fail bdget\n");
    }
    path_put(&root_path);
    return 0;
}

static int main_init(void)
{
    override_sysfs();

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
    sys_call_table = (void *)((unsigned long)ia32_sys_call_table - 4032lu);

    pr_info("Found ia32_sys_call_table: %px\n", ia32_sys_call_table);
    pr_info("Found sys_call_table: %px\n", sys_call_table);

    return override_syscall();
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