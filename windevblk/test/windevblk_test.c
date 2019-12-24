#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include "windevblk.h"


int main()
{
    BOOL bRet;
    DWORD dwReadBytes;
    LARGE_INTEGER lSize, lDist,lPos;
    char* buffer = calloc(100000000, 1);
   /* HANDLE hFile = CreateFile("C:/Developer/Test.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        bRet = ReadFile(hFile, buffer, 125, NULL, NULL);
        if (bRet)
        {
            lDist.QuadPart = 0;
            SetFilePointerEx(hFile, lDist, &lPos, FILE_CURRENT);
        }
    }
    CloseHandle(hFile);*/

    HDEVBLK hDevBlk = DevBlkOpen(0, 1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
    if (hDevBlk != NULL)
    {
        HDEVBLK hDevBlk2 = DevBlkOpen(0, 1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
        HDEVBLK hDevBlk3 = DevBlkOpen(0, 1, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
        bRet = DevBlkIsValidHandle(hDevBlk);

        HANDLE hDisk = DevBlkGetDiskHandle(hDevBlk2);
        
        bRet = DevBlkGetFileSizeEx(hDevBlk2, &lSize);
        hDisk = DevBlkGetDiskHandle(hDevBlk2);
        HDEVBLK hDevtest = DevBlkFromDiskHandle(hDisk);


        // First try to get partition size
        lDist.QuadPart = 0;
        DevBlkSetPointerEx(hDevBlk, lDist, &lPos, FILE_END);
        
        // try to move beyond the partition
        lDist.QuadPart = 1;
        DevBlkSetPointerEx(hDevBlk, lDist, &lPos, FILE_CURRENT);
        
        
        // go back to begining
        lDist.QuadPart = 0;
        DevBlkSetPointerEx(hDevBlk, lDist, &lPos, FILE_BEGIN);

        bRet = DevBlkRead(hDevBlk, buffer, 0, &dwReadBytes, NULL);

        // go back to begining
        lDist.QuadPart = 0;
        DevBlkSetPointerEx(hDevBlk, lDist, &lPos, FILE_BEGIN);

        DWORD dwLen = 26214400;
        bRet = DevBlkRead(hDevBlk, buffer, dwLen, &dwReadBytes, NULL);

        bRet = DevBlkRead(hDevBlk, buffer+ dwLen, dwLen, &dwReadBytes, NULL);

        bRet = DevBlkRead(hDevBlk, buffer, 1, &dwReadBytes, NULL);
        
        lDist.QuadPart = 0;
        DevBlkSetPointerEx(hDevBlk, lDist, &lPos, FILE_CURRENT);

        DevBlkClose(hDevBlk);
    }
    free(buffer);
    getch();
	return 0;
}


