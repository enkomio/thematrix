#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <WinInet.h>
#include <bcrypt.h>

void WinInet_test(void)
{
    HINTERNET hOpen = InternetOpenA(
        NULL, 
        INTERNET_OPEN_TYPE_DIRECT, 
        NULL, 
        NULL, 
        0
    );
    if (!hOpen) return;

    HINTERNET hConnect = InternetConnectA(
        hOpen,
        "www.example.com",
        INTERNET_DEFAULT_HTTP_PORT,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        0
    );
    if (!hConnect) return;

    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        "/",
        NULL,
        NULL,
        NULL,
        INTERNET_FLAG_KEEP_CONNECTION,
        NULL
    );
    if (!hRequest) return;

    if (!HttpSendRequestA(
        hRequest,
        NULL,
        -1,
        0,
        0
    )) return;

    char status_code_str[4] = { 0 };
    DWORD buffer_len = sizeof(status_code_str);
    if (!HttpQueryInfoA(
        hRequest,
        HTTP_QUERY_STATUS_CODE,
        status_code_str,
        &buffer_len,
        NULL
    )) return;
    DWORD status_code = atoi(status_code_str);
    
    if (status_code == 200) {
        char content_length_str[16] = { 0 };
        buffer_len = sizeof(content_length_str);
        if (!HttpQueryInfoA(
            hRequest,
            HTTP_QUERY_CONTENT_LENGTH,
            content_length_str,
            &buffer_len,
            NULL
        )) return;

        size_t content_length = atoi(content_length_str);
        char* content = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, content_length + 1);
        if (!content) return;

        DWORD nRead = 0;
        if (!InternetReadFile(
            hRequest,
            content,
            content_length,
            &nRead
        )) return;
                
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hOpen);
        HeapFree(GetProcessHeap(), 0, content);
    }
}

void VirtualAlloc_test(void)
{
    const size_t size = 0x1000;
    uint8_t* buffer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!buffer) return;

    for (int i = 0; i < size; i++) {
        buffer[i] = (uint8_t)i;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
}

/*
    This function mimic the Emotet encryption code
*/
void BCrypt_test(void)
{
    BCRYPT_ALG_HANDLE hECDHAlgorithm = 0;
    if (BCryptOpenAlgorithmProvider(
        &hECDHAlgorithm,
        BCRYPT_ECDH_P256_ALGORITHM,
        MS_PRIMITIVE_PROVIDER, 
        0)) return;

    BCRYPT_KEY_HANDLE hGenKey = 0;
    if (BCryptGenerateKeyPair(
        hECDHAlgorithm,
        &hGenKey,
        256,
        0
    )) return;

    if (BCryptFinalizeKeyPair(hGenKey, 0)) return;

    uint8_t exported_key[0x48] = { 0 };
    uint32_t ncount = 0;
    if (BCryptExportKey(
        hGenKey,
        0,
        BCRYPT_ECCPUBLIC_BLOB,
        exported_key,
        sizeof(exported_key),
        &ncount,
        0
    )) return;

    // Emotet ECDH key
    uint8_t ecc_key[] = {
        0x45,0x43,0x4b,0x31,0x20,0x00,0x00,0x00,0xf3,0xa3,0x35,0xb5,0x0e,0x2e,0x2b,0xf4,
        0x35,0x56,0xcd,0x0a,0x4c,0x29,0x3e,0x7c,0xf1,0x10,0xdd,0xcb,0xb0,0x4f,0x20,0xb3,
        0xfa,0x02,0x20,0xce,0x4c,0xb6,0x0c,0x1e,0x44,0x96,0xbe,0xb4,0x0e,0xe6,0xc9,0x5b,
        0x9a,0xbd,0x4e,0xbd,0x9d,0x8f,0xcf,0xe0,0x10,0x5b,0x34,0x4c,0x82,0x04,0x26,0x02,
        0xd3,0xba,0xac,0xf1,0xfb,0x9f,0x2c,0x76
    };

    BCRYPT_KEY_HANDLE hImportedKey = 0;
    if (BCryptImportKeyPair(
        hECDHAlgorithm,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        &hImportedKey,
        ecc_key,
        sizeof(ecc_key),
        0
    )) return;

    BCRYPT_SECRET_HANDLE hSecret = 0;
    if (BCryptSecretAgreement(
        hGenKey,
        hImportedKey,
        &hSecret,
        0
    )) return;
    
    BCRYPT_ALG_HANDLE hAesAlgorithm = 0;
    if (BCryptOpenAlgorithmProvider(
        &hAesAlgorithm,
        BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0)) return;
    
    uint8_t pbDerivedKey[0x20] = { 0 };
    BCryptBufferDesc parameterDesc = { 0 };
    BCryptBuffer paramList[1] = { 0 };

    paramList[0].BufferType = KDF_HASH_ALGORITHM;
    paramList[0].cbBuffer = (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    paramList[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

    parameterDesc.cBuffers = 1;
    parameterDesc.pBuffers = paramList;
    parameterDesc.ulVersion = BCRYPTBUFFER_VERSION;

    if (BCryptDeriveKey(
        hSecret,
        BCRYPT_KDF_HASH,
        &parameterDesc,
        pbDerivedKey,
        sizeof(pbDerivedKey),
        &ncount,
        0
    )) return;

    uint32_t object_size = 0;
    if (BCryptGetProperty(
        hAesAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        &object_size,
        sizeof(object_size),
        &ncount,
        0
    )) return;

    PVOID obj_blob = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, object_size);
    if (!obj_blob) return;

    BCRYPT_KEY_HANDLE hDerivedKey = 0;
    uint8_t data_blob[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + sizeof(pbDerivedKey)] = {0};
    ((BCRYPT_KEY_DATA_BLOB_HEADER*)data_blob)->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    ((BCRYPT_KEY_DATA_BLOB_HEADER*)data_blob)->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    ((BCRYPT_KEY_DATA_BLOB_HEADER*)data_blob)->cbKeyData = sizeof(pbDerivedKey);
    memcpy(data_blob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), pbDerivedKey, sizeof(pbDerivedKey));

    if (BCryptImportKey(
        hAesAlgorithm,
        0,
        BCRYPT_KEY_DATA_BLOB,
        &hDerivedKey,
        obj_blob,
        object_size,
        data_blob,
        sizeof(data_blob),
        0
    )) return;

    char plain_secret_text[] = "This is a sample text that must be encrypted with the session key!";
    char* encrypted_secret_text = NULL;
    if (BCryptEncrypt(
        hDerivedKey,
        plain_secret_text,
        sizeof(plain_secret_text),
        NULL,
        NULL,
        0,
        NULL,
        0,
        &ncount,
        BCRYPT_BLOCK_PADDING
    )) return;

    size_t encrypted_secret_text_size = ncount;
    encrypted_secret_text = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, encrypted_secret_text_size);
    if (!encrypted_secret_text) return;

    if (BCryptEncrypt(
        hDerivedKey,
        plain_secret_text,
        sizeof(plain_secret_text),
        NULL,
        NULL,
        0,
        encrypted_secret_text,
        encrypted_secret_text_size,
        &ncount,
        BCRYPT_BLOCK_PADDING
    )) return;

    // decrypt the same text
    if (BCryptDecrypt(
        hDerivedKey,
        encrypted_secret_text, 
        encrypted_secret_text_size,
        NULL,
        NULL,
        0,
        0,
        0,
        &ncount,
        BCRYPT_BLOCK_PADDING
    )) return;

    PVOID decrypted_text = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ncount);
    if (!decrypted_text) return;

    if (BCryptDecrypt(
        hDerivedKey,
        encrypted_secret_text,
        encrypted_secret_text_size,
        NULL,
        NULL,
        0,
        decrypted_text,
        ncount,
        &ncount,
        BCRYPT_BLOCK_PADDING
    )) return;

    // verify
    if (strcmp(decrypted_text, plain_secret_text, sizeof(plain_secret_text)))
        return;
       
    // clean-up
    HeapFree(GetProcessHeap(), 0, obj_blob);    
    HeapFree(GetProcessHeap(), 0, encrypted_secret_text);
    HeapFree(GetProcessHeap(), 0, decrypted_text);
    BCryptDestroyKey(hDerivedKey);
    BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hGenKey);
    BCryptDestroyKey(hImportedKey);
    BCryptCloseAlgorithmProvider(hAesAlgorithm, 0);
    BCryptCloseAlgorithmProvider(hECDHAlgorithm, 0);   
}

void WriteFile_test(void)
{
    char DataBuffer[] = "This is a simple text";
    int dwBytesToWrite = sizeof(DataBuffer);
    int dwBytesWritten = 0;

    HANDLE hFile = CreateFile(
        L"test.txt",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    WriteFile(
        hFile,           // open file handle
        DataBuffer,      // start of data to write
        dwBytesToWrite,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure

    CloseHandle(hFile);
    DeleteFile(L"test.txt");
}

int main(void)
{
    printf("Start test functions\n");
    BCrypt_test();
    WinInet_test();
    VirtualAlloc_test();   
    WriteFile_test();
    return 0;
}