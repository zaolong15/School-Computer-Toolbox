#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    unsigned __int64 baseLBA = 0;
    DWORD dwBytesReturned;
    for (int diskIndex = 0; diskIndex < 20; ++diskIndex) {
        char deviceName[50];
        sprintf(deviceName, "\\\\.\\PhysicalDrive%d", diskIndex);
      
        hDevice = CreateFileA(deviceName, 
                              GENERIC_READ | GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, 
                              OPEN_EXISTING, 
                              0, 
                              NULL);
      
        if (hDevice == INVALID_HANDLE_VALUE) {
            continue;
        }

        __int64 inBuffer = 0;
        BOOL bResult = DeviceIoControl(hDevice, 0x72054, &inBuffer, 8, &inBuffer, 8, &dwBytesReturned, NULL);
      
        if (bResult && inBuffer != 0) {
            baseLBA = inBuffer;
            printf("Found Zengba Card data on PhysicalDrive%d. Base LBA: %llu\n", diskIndex, baseLBA);
            break;
        }
      
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
    }

    if (baseLBA == 0) {
        printf("Error: Could not find a drive with Zengba Card data.\n");
        return 1;
    }
    BYTE sectorBuffer[512] = {0};
    DWORD* pBuffer = (DWORD*)sectorBuffer;
    unsigned __int64 targetLba = baseLBA + 6410;
    pBuffer[0] = (DWORD)targetLba;
    pBuffer[1] = (DWORD)(targetLba >> 32);
    pBuffer[2] = 1;

    printf("Reading sector at LBA: %llu\n", targetLba);
    BOOL bResult = DeviceIoControl(hDevice, 0x7201C, sectorBuffer, 512, sectorBuffer, 512, &dwBytesReturned, NULL);
  
    if (!bResult) {
        printf("Error: Failed to read sector. LastError: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }
    printf("Decrypting password...\n");
    pBuffer[0] ^= 0x48414947u;
    pBuffer[1] ^= 0x55414E47u;

    printf("\n--- Password Found ---\n");
    printf("Hexadecimal (first 32 bytes): ");
    for (int i = 0; i < 32; ++i) {
        printf("%02X ", sectorBuffer[i]);
    }
    printf("\n");
  
    printf("Password as String: %s\n", (char*)sectorBuffer);
    printf("----------------------\n");

    CloseHandle(hDevice);
    return 0;
}

