#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/*
How to parse
- /sys/block/sda/device/vpd_pg80
00000000  00 80 00 14 51 4d 30 30  30 30 31 20 20 20 20 20  |....QM00001     |
00000010  20 20 20 20 20 20 20 20                           |        |

00000000  00 80 00 14 53 32 50 57  4e 58 30 48 41 30 39 33  |....S2PWNX0HA093|
00000010  37 35 48 20 20 20 20 20                           |75H     |

- /sys/block/sda/device/vpd_pg83
- /sys/block/sda/device/vpd_pg89

Compile:
    gcc -static -m32 -o root/test_funct test_funct.c

Watch:
    while true; do
        gcc -o test_funct test_funct.c && ./test_funct || echo "ERR $?"
        inotifywait -e close_write -q test_funct.c
        sleep 0.3
    done
*/

static char buf[BUFSIZ];
struct page80
{
    u_int8_t qualifierType;
    u_int8_t code;
    u_int8_t len_msb; // reserverd
    u_int8_t len_lsb;
    char body[];
};

// https://github.com/hreinecke/sg3_utils/blob/master/src/sg_vpd.c
struct page83
{
    u_int8_t qualifierType;
    u_int8_t code;
    u_int8_t len_msb; // reserverd
    u_int8_t len_lsb;
    char body[];
};

// https://www.t10.org/ftp/t10/document.04/04-219r3.pdf
struct page89
{
    u_int8_t qualifierType;
    u_int8_t code;
    u_int8_t len_msb;
    u_int8_t len_lsb;
    char reserved[4];
    char vendor[8];
    char product[16];
    char revision[4];
    char signature[20];
    char cmd_code;     // 56
    char reserved2[4]; // 57 - 59
    char data[];       // 60
};
union page
{
    struct page80 page80;
    struct page83 page83;
    struct page89 page89;
};

int readPage(int pgCode)
{
    char cmd[36];
    int fd, n;
    snprintf(cmd, 35, "hd /sys/block/sdb/device/vpd_pg%02x", pgCode);

    printf("\nREAD %s\n", cmd + 3);
    system(cmd);

    fd = open(cmd + 3, O_RDONLY);

    if (fd < 0)
    {
        perror("open");
        exit(errno);
    }

    memset(buf, 0, BUFSIZ);
    n = read(fd, buf, BUFSIZ);

    if (n < 0)
    {
        perror("read");
        exit(errno);
    }
    close(fd);
    return n;
}

int decode_dev_ids(u_int8_t *buf, int buf_len)
{
    int off, c_set, assoc, desig_type, p_id, piv, is_sas, i_len;
    const u_int8_t *bp;
    const u_int8_t *ip;
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
            printf("DONE AT %d\n", off);
            break;
        }
        bp = buf + off;
        i_len = bp[3];

        printf("\toff %d, len %d, ", off, i_len);
        // off = off + i_len;
        ip = bp + 4;
        p_id = ((bp[0] >> 4) & 0xf);
        c_set = (bp[0] & 0xf);
        piv = ((bp[1] & 0x80) ? 1 : 0);
        is_sas = (piv && (6 == p_id)) ? 1 : 0;
        assoc = ((bp[1] >> 4) & 0x3);
        desig_type = (bp[1] & 0xf);
        printf("code_set %d, assoc %d, desig_type %d ", c_set, assoc, desig_type);
        switch (desig_type)
        {
        case 0: /* vendor specific */
        case 1: /* T10 vendor identification */
            printf("%.*s\n", i_len, ip);
            break;
        case 2:   /* EUI-64 based */
        case 3:   /* NAA */
        case 4:   /* Relative target port */
        case 5:   /* (primary) Target port group */
        case 6:   /* Logical unit group */
        case 7:   /* MD5 logical unit identifier */
        case 8:   /* SCSI name string */
        case 9:   /* Protocol specific port identifier */
        case 0xa: /* UUID identifier [spc5r08] RFC 4122 */
        default:  /* reserved */
            printf(" **Ignored\n");
            break;
        }
    }
}
/* Extract character sequence from ATA words as in the model string
 * in a IDENTIFY DEVICE response. Returns number of characters
 * written to 'ochars' before 0 character is found or 'num' words
 * are processed. */
int sg_ata_get_chars(const u_int16_t *word_arr, int start_word,
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
int sg_ata_put_chars(const u_int16_t *word_arr, int start_word,
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
// https://www.t10.org/ftp/t10/document.04/04-219r3.pdf

void decode_ata_info(u_int8_t *buf, int len)
{
    int cc;
    char tmp[80];
    const char *cp;
    const char * fake_model = "ASDFGHJK                                ";
    const char * fake_serial = "XYZ-SERIAL          ";
    cp = (0x34 == buf[36]) ? "SATA" : "PATA";
    printf("vendor: %.8s, product: %.16s, revision: %.4s, trans: %s\n",
           buf + 8,
           buf + 16,
           buf + 32,
           cp);
    if (len < 56)
    {
        printf("**No more info\n");
        return;
    }
    cc = buf[56]; /* 0xec for IDENTIFY DEVICE and 0xa1 for IDENTIFY
                   * PACKET DEVICE (obsolete) */
    printf("  Command code: 0x%x\n", cc);
    if (len < 60)
    {
        printf("**No more info\n");
        return;
    }
    if (0xec == cc)
        cp = "";
    else if (0xa1 == cc)
        cp = "PACKET ";
    else
        cp = NULL;
    int is_be = 0;
    if (cp)
    {
        printf("  ATA command IDENTIFY %sDEVICE response summary:\n", cp);
        //cc = sg_ata_put_chars((const unsigned short *)(buf + 60), 27, 20, is_be, fake_model);
        cc = sg_ata_get_chars((const unsigned short *)(buf + 60), 27, 20,
                              is_be, tmp);
        tmp[cc] = '\0';
        printf("    model: %s\n", tmp);

        //cc = sg_ata_put_chars((const unsigned short *)(buf + 60), 10, 10, is_be, fake_serial);
        cc = sg_ata_get_chars((const unsigned short *)(buf + 60), 10, 10,
                              is_be, tmp);
        tmp[cc] = '\0';
        printf("    serial number: %s\n", tmp);

        cc = sg_ata_get_chars((const unsigned short *)(buf + 60), 23, 4,
                              is_be, tmp);
        tmp[cc] = '\0';
        printf("    firmware revision: %s\n", tmp);

    }
    else
    {
        printf("Unkown data");
    }
}

int main(int argc, char **argv)
{
    union page *p = (void *)buf;
    int i;
    u_int16_t len;

    i = readPage(0x80);
    len = (p->page80.len_msb << 8) | p->page80.len_lsb;
    printf("Size: %d, Code: %02xh, Body %d, sn: %s\n", i, p->page80.code, len, &p->page80.body);

    i = readPage(0x83);
    len = (p->page83.len_msb << 8) | p->page83.len_lsb;
    printf("Size: %d, Code: %02xh, Body %d\n", i, p->page83.code, len);
    decode_dev_ids(p->page83.body, len);

    i = readPage(0x89);
    len = (p->page89.len_msb << 8) | p->page89.len_lsb;
    printf("Size: %d, Code: %02xh, Body %d\n", i, p->page89.code, len);
    decode_ata_info((void *) &p->page89, len);

    printf("DONE\n");
    return 0;
}