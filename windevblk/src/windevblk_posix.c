#include <windows.h>
#include <assert.h>
#include "windevblk.h"
#include "windevblk_list.h"
#include "list.h"

#include "get_osfhandle-nothrow.h"

#include <unistd.h>
#include <fcntl.h>

extern PSMI_RAWDEV_ENTRY g_devblk_array[128];
static CRITICAL_SECTION g_critSec;

int __cdecl devblk_open2(const char* pathname, int flags, mode_t mode);

int __cdecl devblk_open(const char* pathname, int flags, ...)
{
    mode_t mode = 0;

    if ((_O_CREAT & flags) != 0)
    {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    return devblk_open2(pathname, flags, mode);
}


int __cdecl devblk_open2(const char* pathname, int flags, mode_t mode)
{
    int fd = -1;
    char * pEnd;
    int deviceIndex, partitionIndex;
    HDEVBLK hDevBlk;
    HANDLE hDisk;

    if (!pathname)
        return ENOENT;

    deviceIndex = pathname[7] - 'a';
    partitionIndex = strtol(pathname + 8, &pEnd, 10);

    hDevBlk = DevBlkOpen(deviceIndex, partitionIndex, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
    if (hDevBlk)
    {
        hDisk = DevBlkGetDiskHandle(hDevBlk);
        fd = _open_osfhandle((intptr_t)hDisk, 0);
    }

    return fd;
}


int __cdecl devblk_close(int fd)
{
    int ret;
    HDEVBLK hDevBlk;
    PDEVBLK_OBJECT devBlkObj;

    hDevBlk = DevBlkFromDiskHandle((HANDLE)_get_osfhandle(fd));
    if (hDevBlk == NULL)
        return -1;
    if (!DevBlkClose(hDevBlk))
        return -1;

    return 0;
}

int __cdecl devblk_fstat(int fd, struct _stat *buf)
{
    HDEVBLK hDevBlk;
    PDEVBLK_OBJECT devBlkObj;

    hDevBlk = DevBlkFromDiskHandle((HANDLE)_get_osfhandle(fd));
    if (hDevBlk == NULL)
        return -1;
    devBlkObj = GetDevBlkObjectPtr(hDevBlk);
    if (!devBlkObj)
        return -1;

    if (buf)
    {
        buf->st_dev = 6;
        buf->st_ino = 0;
        buf->st_nlink = 1;
        buf->st_mode = 0060000; /*S_IFBLK*/
        buf->st_uid = 0;
        buf->st_gid = 6;
        buf->st_rdev = devBlkObj->DevBlk->RootDev;
        buf->st_size = 0;
    }

    return 0;
}


