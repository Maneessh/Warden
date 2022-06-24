#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h> 

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;
#define EA_INFO_LEN(ea) (FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + ea->EaNameLength + ea->EaValueLength+2)

const DWORD s_HMacSecretSize = 32;
const CHAR s_HMacSecret[33] = "eY)#{VXx/L45M7R*~ty,y3EbA~JFL34@";
#define BLOCK_SIZE 0x100000  // 1024*1024  = 1048576 1MB
const CHAR s_HashEaName[] = "WARDENSIGN";


typedef NTSTATUS(*NtSetEaFileProc)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
NtSetEaFileProc NtSetEaFile = NULL;

BOOLEAN GetNTFunctionsAddress()
{
	HMODULE hNTdll = GetModuleHandleA("Ntdll.dll");
	if (!hNTdll)
		return FALSE;
	NtSetEaFile = (NtSetEaFileProc)GetProcAddress(hNTdll, "NtSetEaFile");
	if (!NtSetEaFile)
		return FALSE;
	return TRUE;
}
HANDLE FileOpen(const char* filename)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwDesiredAccess = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;;
	DWORD dwShareMode = FILE_SHARE_READ;

	hFile = CreateFileA(filename,
		dwDesiredAccess,
		dwShareMode,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open %s \t lasterror = %d\n", filename, GetLastError());
	}

	return hFile;
}

VOID DestroyHashHandle(BCRYPT_ALG_HANDLE hHashAlgo, BCRYPT_HASH_HANDLE hHash)
{
	if (!hHash)
		BCryptDestroyHash(hHash);
	if (!hHashAlgo)
		BCryptCloseAlgorithmProvider(hHashAlgo, 0);
}

BOOL CreateCryptoHashHandle(BCRYPT_ALG_HANDLE* phHashAlgo, BCRYPT_HASH_HANDLE* phHash, DWORD* phashLength)
{
	NTSTATUS status = 0;
	BCRYPT_ALG_HANDLE hHashAlgo = NULL;
	BCRYPT_HASH_HANDLE  hHash = NULL;
	DWORD          hashLength = 0;
	DWORD          ResultLength = 0;
	if (!phHashAlgo || !phHash || !phashLength)
		return FALSE;

	status = BCryptOpenAlgorithmProvider(&hHashAlgo, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!NT_SUCCESS(status))
	{
		printf("BCryptOpenAlgorithmProvider returned %0x\n", status);
		return FALSE;
	}
	status = BCryptGetProperty(hHashAlgo, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLength, sizeof(hashLength), &ResultLength, 0);
	if (!NT_SUCCESS(status))
	{
		printf("BCryptGetProperty return %0x\n", status);
		BCryptCloseAlgorithmProvider(hHashAlgo, 0);
		return FALSE;
	}

	status = BCryptCreateHash(hHashAlgo, &hHash, NULL, 0, (PUCHAR)s_HMacSecret, s_HMacSecretSize, 0);
	if (!NT_SUCCESS(status))
	{
		printf("BCryptCreateHash returns= %0x\n", status);
		BCryptCloseAlgorithmProvider(hHashAlgo, 0);
		return FALSE;
	}
	*phHashAlgo = hHashAlgo;
	*phHash = hHash;
	*phashLength = hashLength;
	return TRUE;
}

int EncodeHash(PUCHAR data, ULONG size, char** pEncodedString, DWORD* pEncodedLen)
{
	const char nibble[] = "0123456789ABCDEF";
	PCHAR buff = NULL;
	int l = 0;
	ULONG  encodedLen = size * 2 ;
	if (!pEncodedString || !pEncodedLen)
		return -1;

	buff = (PCHAR)calloc(encodedLen + 1, 1); /// 1 extra byte for null char
	if (!buff)
		return -2;

	for (int i = 0; i < (int)size; i++)
	{
		buff[l++] = nibble[data[i] / 16];
		buff[l++] = nibble[data[i] % 16];
	}
	buff[l] = '\0';

	*pEncodedLen = encodedLen;
	*pEncodedString = buff;
	return l;
}
BOOLEAN HashData(BCRYPT_HASH_HANDLE hHash, PUCHAR data, DWORD dataLen)
{
	NTSTATUS status = BCryptHashData(hHash, data, dataLen, 0);
	if (!NT_SUCCESS(status))
	{
		printf("BCryptHashData returns= %0x\n", status);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN ComputeEncodedHMac(BCRYPT_HASH_HANDLE hHash, DWORD hashLength, char** pEncodedString, DWORD* pEncodedLen)
{
	UCHAR fileHash[100];
	NTSTATUS status = 0;
	if (!pEncodedString || !pEncodedLen)
		return FALSE;
	status = BCryptFinishHash(hHash, fileHash, hashLength, 0);
	if (!NT_SUCCESS(status))
	{
		printf("BCryptFinishHash returns= %0x\n", status);
		return FALSE;
	}
	return EncodeHash(fileHash, hashLength, pEncodedString, pEncodedLen);
}

BOOLEAN SetEaHashAttribute(HANDLE fileHandle, char* hmac, ULONG hmacLen)
{
	BOOLEAN ret = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock = { 0, };
	PFILE_FULL_EA_INFORMATION eaWithHmacBuff = NULL;

	ULONG  eaWithHmacBuffLen = (ULONG)(FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
		hmacLen + 1 +
		strlen(s_HashEaName) + 1);

	eaWithHmacBuff = calloc(eaWithHmacBuffLen, 1);
	if (!eaWithHmacBuff)
	{
		printf("Out of Memory\n ");
		return ret;
	}

	eaWithHmacBuff->EaNameLength = (UCHAR)strlen(s_HashEaName);
	eaWithHmacBuff->EaValueLength = (UCHAR)hmacLen;
	memcpy(eaWithHmacBuff->EaName, s_HashEaName, eaWithHmacBuff->EaNameLength);
	memcpy(eaWithHmacBuff->EaName + eaWithHmacBuff->EaNameLength + 1, hmac, hmacLen);

	status = NtSetEaFile(fileHandle, &ioStatusBlock, eaWithHmacBuff, eaWithHmacBuffLen);
	if (!NT_SUCCESS(status))
	{
		printf("NtSetEaFile returns= %0x\n", status);
		goto end;
	}
	ret = TRUE;
end:

	if (!eaWithHmacBuff)
		free(eaWithHmacBuff);
	return ret;
}


BOOLEAN FileSign(const char* filename)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BCRYPT_ALG_HANDLE hHashAlgo = NULL;
	BCRYPT_HASH_HANDLE  hHash = NULL;
	DWORD          hashLength = 0;
	NTSTATUS status = 0;

	char* buff = NULL;
	DWORD buffLen = BLOCK_SIZE;
	DWORD bytesRead = 0;
	int nomore = 0;
	char* encodedHash = NULL;
	DWORD encodedHashLen = 0;

	if (!CreateCryptoHashHandle(&hHashAlgo, &hHash, &hashLength))
		goto end;
	hFile = FileOpen(filename);
	if (hFile == INVALID_HANDLE_VALUE)
		goto end;
	buff = (char*)malloc(buffLen * sizeof(char));
	do
	{
		SetLastError(0);
		buffLen = BLOCK_SIZE;
		memset(buff, 0, buffLen);
		if ((!ReadFile(hFile, buff, buffLen, &bytesRead, NULL)) || (!bytesRead))
		{
			printf("\n err:%8d bytes read :%10d\n", GetLastError(), bytesRead);
			nomore = 1;
		}
		if (bytesRead > 0)
		{
			NTSTATUS status = BCryptHashData(hHash, buff, bytesRead, 0);
			if (!NT_SUCCESS(status))
			{
				printf("BCryptHashData returns= %0x\n", status);
				goto end;
			}
		}
	} while (!nomore);
	
	if (!ComputeEncodedHMac(hHash, hashLength, &encodedHash, &encodedHashLen))
	{
		printf("ComputeEncodedHMac Failed\n");
		goto end;
	}
	if (!SetEaHashAttribute(hFile, encodedHash, encodedHashLen))
	{
		printf("SetHashExAttribute Failed\n");
		goto end;
	}
	printf("Hash Ea Attribute Sucessfully set\n");

end:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	DestroyHashHandle(hHashAlgo, hHash);
	if (encodedHash)
		free(encodedHash);
	return FALSE;
}
 

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("Usage: WardenApp FileToSign\n");
		return 0;
	}
	if (!GetNTFunctionsAddress())
	{
		printf("Platform not supported\n");
		return 0;
	}
	FileSign(argv[1]);
	return 0;
}


