#include <stdio.h>
#include <linux/fcntl.h>
#include <linux/ioctl.h>
#include <linux/hdreg.h>

// Compile : gcc -static -m32 -o root/test_ioctl test_ioctl.c
int main(int argc, char ** argv)
{
    struct hd_driveid hd;
    char *dev = argv[1];
    int fd, ret;
    if (argc <= 1)
    {
        dev = "/dev/sdb";
    }
    if ((fd = open(dev, O_RDONLY | O_NONBLOCK)) < 0)
    {
        printf("ERROR opening %s\n", dev);
        return -1;
    }
    else
    {
        ret = ioctl(fd, HDIO_GET_IDENTITY, &hd);
        if (ret == 0)
        {
            printf("%.20s , %.20s\n", hd.model, hd.serial_no);
        }
        else
        {
            printf("Failed: %i\n", ret);
        }
        return ret;
    }
}