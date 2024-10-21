#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system headers
//
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <cstdio>

//
// stardust headers
//
#include <Native.h>
#include <Macros.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>
#include <Config.h>

//
// stardust instances
//
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    //
    // base address and size
    // of the implant
    //
    BUFFER Base;

    struct {

        //
        // Ntdll.dll
        //
        D_API( RtlAllocateHeap        )
        D_API( NtProtectVirtualMemory )

        //
        // kernel32.dll
        //
        D_API( LoadLibraryW )
        D_API( VirtualAlloc )
        D_API( VirtualProtect )
        D_API( VirtualFree )
        D_API( GetLastError )

        //
        // User32.dll
        //
        D_API( MessageBoxA )

        //
        // Msvcrt.dll
        //
        D_API ( strlen );
        D_API ( strcmp)
        D_API ( sprintf );
        D_API ( calloc );
        D_API ( memset );
        D_API ( free );

        //
        // Wininet.dll
        //
        D_API( InternetOpenA );
        D_API( InternetConnectA );
        D_API( HttpOpenRequestA );
        D_API( HttpSendRequestA );
        D_API( HttpQueryInfoA );
        D_API( InternetQueryOptionA );
        D_API( InternetSetOptionA );
        D_API( InternetReadFile );
        D_API( InternetCloseHandle );

        //
        // Advapi.dll
        //
        D_API( CryptAcquireContextA );
        D_API( CryptCreateHash );
        D_API( CryptHashData );
        D_API( CryptGetHashParam );
        D_API( CryptDestroyHash );
        D_API( CryptReleaseContext );

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID User32;
        PVOID Msvcrt;
        PVOID Wininet;
        PVOID Advapi32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main(
    _In_ PVOID Param
);

#define MD5LEN  16

#endif //STARDUST_COMMON_H
