#ifndef _WINDEVBLK_
#define _WINDEVBLK_
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winioctl.h>

#include <sys/types.h>  
#include <sys/stat.h>  

#ifdef  __cplusplus
extern "C" {
#endif

	typedef void* HDEVBLK;

    typedef struct _SMI_ENUMDRIVE_INFO
    {
        DWORD u32DeviceNumber;
        CHAR szSerialNumber[1000];
        CHAR szModelNumber[1000];
        CHAR szVendorId[1000];
        CHAR szProductRevision[1000];
        CHAR szDevicePath[1000];
        CHAR szShortDevicePath[MAX_PATH + 1];
        INT	canBePartitioned;
        DWORD BytesPerSector;
        LARGE_INTEGER DiskSize;
        DWORD PartitionStyle;
        DWORD PartitionCount;
    } SMI_ENUMDRIVE_INFO, *PSMI_ENUMDRIVE_INFO;


    typedef struct _SMI_DEVBLK_INFO
    {
        PVOID Unused;
        DWORD DeviceNumber;
        DWORD PartitionNumber;
        BOOLEAN RewritePartition;
        INT PartitionStyle;
        LARGE_INTEGER PartitionLength;
        LARGE_INTEGER StartingOffset;
        LARGE_INTEGER EndingOffset;
        union {
            PARTITION_INFORMATION_MBR Mbr;
            PARTITION_INFORMATION_GPT Gpt;
        } DUMMYUNIONNAME;

        // Posix info
        CHAR    PosixName[64];    // ex sda2
        UINT    RootDev;          // Major/Minor

        // Volume info
        CHAR    szRootPathName[MAX_PATH + 1];
        CHAR	szVolumeName[MAX_PATH + 1];
        CHAR	szVolumePathName[MAX_PATH + 1];
        CHAR	szFileSystemName[MAX_PATH + 1];
        DWORD	dwSerialNumber;
        DWORD	dwFileSystemFlags;
    }	SMI_DEVBLK_INFO, *PSMI_DEVBLK_INFO;

    BOOL DevBlkEnumDrives(
        _Out_ LPBYTE  pDriveInfoArray,
        _In_  DWORD   cbBuf,
        _Out_ LPDWORD pcbNeeded,
        _Out_ LPDWORD pcReturned
    );


    BOOL DevBlkEnumDevices(
        _Out_ LPBYTE  pDevBlkArray,
        _In_  DWORD   cbBuf,
        _Out_ LPDWORD pcbNeeded,
        _Out_ LPDWORD pcReturned
    );

	
	HDEVBLK WINAPI DevBlkOpen(
		_In_ INT iDevBlkNumber, /* iDevBlkNumber is the device number ie 0 opens \\\\.\\PhysicalDrive0 */
		_In_ INT iPartitionNumber,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode
	);

    // BIG WARNING: Do not call
    HANDLE WINAPI DevBlkGetDiskHandle(
        _In_      HDEVBLK        hDevBlk
    );

    HDEVBLK WINAPI DevBlkFromDiskHandle(
        _In_      HANDLE        hDrive);

	BOOL WINAPI DevBlkIsValidHandle(
		_In_      HDEVBLK        hDevBlk
	);

    BOOL WINAPI DevBlkGetFileSizeEx(
        _In_  HDEVBLK        hFile,
        _Out_ PLARGE_INTEGER lpFileSize
    );


    
   DWORD WINAPI DevBlkSetPointer(
        _In_ HDEVBLK hDevBlk,
        _In_ LONG lDistanceToMove,
        _Inout_opt_ PLONG lpDistanceToMoveHigh,
        _In_ DWORD dwMoveMethod
        );

	BOOL WINAPI DevBlkSetPointerEx(
		_In_      HDEVBLK        hDevBlk,
		_In_      LARGE_INTEGER  liDistanceToMove,
		_Out_opt_ PLARGE_INTEGER lpNewFilePointer,
		_In_      DWORD          dwMoveMethod
	);

	BOOL WINAPI DevBlkRead(
		_In_        HDEVBLK      hDevBlk,
		_Out_       LPVOID       lpBuffer,
		_In_        DWORD        nNumberOfBytesToRead,
		_Out_opt_   LPDWORD      lpNumberOfBytesRead,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
	);

	BOOL WINAPI DevBlkWrite(
		_In_        HDEVBLK      hDevBlk,
		_In_        LPCVOID      lpBuffer,
		_In_        DWORD        nNumberOfBytesToWrite,
		_Out_opt_   LPDWORD      lpNumberOfBytesWritten
	);

	BOOL WINAPI DevBlkClose(
		_In_ HDEVBLK hObject
	);

    // Posix subsystem
    int __cdecl devblk_open(const char* pathname, int flags, ...);
    
    int __cdecl devblk_fstat(int fd, struct _stat *buf);
    int __cdecl devblk_close(int fd);

#ifdef  __cplusplus
}
#endif






#endif /*_WINDEVBLK_*/