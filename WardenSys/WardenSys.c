/*++

Module Name:

	sys.c

Abstract:

	This is the main module of the sys miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <bcrypt.h>

#define TAG_WARDEN 'draW'
const ULONG s_HMacSecretSize = 32;
const CHAR s_HMacSecret[33] = "eY)#{VXx/L45M7R*~ty,y3EbA~JFL34@";
CHAR s_HashEaName[] = "WARDENSIGN";
#define BLOCK_SIZE 0x100000  // 1024*1024  = 1048576 1MB
 
const ANSI_STRING s_HashAtrributeName = RTL_CONSTANT_STRING(s_HashEaName);
UNICODE_STRING s_WardenNtDevName = RTL_CONSTANT_STRING(L"\\Device\\Warden");
UNICODE_STRING s_WardenDosLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\Warden");
BCRYPT_ALG_HANDLE s_HashAlgoHandle = NULL;
ULONG s_HashLength = 0;
BOOLEAN s_bDosDevLinkCreated = FALSE;
BOOLEAN s_bNtDeviceCreated = FALSE;
BOOLEAN s_bProcessCBRegisterd = FALSE;
BOOLEAN s_bCryptoInitialized = FALSE;

NTSTATUS InitilizeCrypto()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ResultLength = 0;
	status = BCryptOpenAlgorithmProvider(&s_HashAlgoHandle, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": BCryptOpenAlgorithmProvider return %0x \n", status);
		return status;
	}
	status = BCryptGetProperty(s_HashAlgoHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&s_HashLength, sizeof(s_HashLength), &ResultLength, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": BCryptGetProperty return %0x \n", status);
		BCryptCloseAlgorithmProvider(s_HashAlgoHandle, 0);
		return status;
	}
	return STATUS_SUCCESS;
}

int EncodeHash(PUNICODE_STRING encodedString,PUCHAR data,ULONG size)
{
	const wchar_t nibble[] = L"0123456789ABCDEF";
	PWCHAR buff = NULL;
	int l = 0;
	ULONG  encodedLen = (size * 2 + 1) * sizeof(WCHAR);
	if(!encodedString)
		return -1;

	buff = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, encodedLen, TAG_WARDEN);
	if (!buff)
		return -2;

	for (int i = 0; i < (int)size; i++) 
	{
		buff[l++] = nibble[data[i] / 16];
		buff[l++] = nibble[data[i] % 16];
	}
	buff[l] = L'\0';

	encodedString->Length = (USHORT)(l * sizeof(WCHAR));
	encodedString->MaximumLength =  (USHORT)encodedLen;
	encodedString->Buffer = buff;
	return l;
}

NTSTATUS CalculateFileHash(HANDLE fileHandle, PUNICODE_STRING fileEncodedHash)
{
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock = { 0, };
	LARGE_INTEGER   offset = { 0, };
	ULONG			readBuffLen = BLOCK_SIZE;
	PUCHAR			readBuff = NULL;
	ULONG			bytesRead = 0;
	BOOLEAN			bEOF = FALSE;
	UCHAR			fileHash[200];
	BCRYPT_HASH_HANDLE  hHash = NULL;
	status = BCryptCreateHash(s_HashAlgoHandle, &hHash, NULL, 0, (PUCHAR)s_HMacSecret, s_HMacSecretSize, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": "" BCryptCreateHash returns= %0x \n", status);
		return status;
	}

	readBuff = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, readBuffLen, TAG_WARDEN);
	if (!readBuff)
	{
		DbgPrint(__FUNCTION__": "" ExAllocatePoolWithTag returns NULL");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	do {
		status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, readBuff, readBuffLen, &offset, NULL);
		DbgPrint(__FUNCTION__": "" ZwReadFile returns= %0x ioStatusBlock = %0x \n", status, ioStatusBlock.Status);
		if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE)
		{
			DbgPrint(__FUNCTION__": "" ZwReadFile returns= %0x \n", status);
			goto end;
		}
		if (status == STATUS_END_OF_FILE || ioStatusBlock.Status == STATUS_END_OF_FILE)
			bEOF = TRUE;
		bytesRead = (ULONG)ioStatusBlock.Information;
		status = BCryptHashData(hHash, readBuff, bytesRead, 0);	
		if (!NT_SUCCESS(status))
		{			
			DbgPrint(__FUNCTION__": "" BCryptHashData returns= %0x \n", status);
			goto end;
		}
		offset.QuadPart += bytesRead;
		RtlZeroBytes(readBuff, readBuffLen);

	} while (!bEOF);
	status = BCryptFinishHash(hHash, fileHash, s_HashLength, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": "" BCryptFinishHash returns= %0x \n", status);
		goto end;
	}

	EncodeHash(fileEncodedHash, fileHash, s_HashLength);
	status = STATUS_SUCCESS;
end:
	if (!readBuff)
	{
		ExFreePoolWithTag(readBuff, TAG_WARDEN);
	}

	if (!hHash)
		BCryptDestroyHash(hHash);
	return status;
}

NTSTATUS QueryHashEaAtrrib(HANDLE fileHandle, PUNICODE_STRING encodedHash)
{
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock = { 0, };
	PFILE_FULL_EA_INFORMATION eaBuff = NULL;
	PFILE_FULL_EA_INFORMATION ea = NULL;
	FILE_EA_INFORMATION fileEaInfo;
	PUCHAR eaBoundary = NULL; 
	STRING eaName = { 0, };
	STRING eaValue = { 0, };
	if (!encodedHash) 
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = ZwQueryInformationFile(fileHandle,
		&ioStatusBlock,
		&fileEaInfo,
		sizeof(FILE_EA_INFORMATION),
		FileEaInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": "" ZwQueryInformationFile returns= %0x \n", status);
		return status;
	}
	DbgPrint(__FUNCTION__": "" ZwQueryInformationFile returns= %d \n", fileEaInfo.EaSize);
	eaBuff = (PFILE_FULL_EA_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, fileEaInfo.EaSize, TAG_WARDEN);
	if (!eaBuff)
	{
		DbgPrint(__FUNCTION__": "" ExAllocatePoolWithTag returns NULL");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	 
	status = ZwQueryEaFile(fileHandle, &ioStatusBlock, eaBuff, fileEaInfo.EaSize, FALSE, NULL, 0, NULL, TRUE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__": "" ZwQueryEaFile returns= %0x \n", status);
		goto end;
	}
	ea = eaBuff;
	eaBoundary = (PUCHAR)eaBuff + fileEaInfo.EaSize;
	while ((PUCHAR)ea < eaBoundary)
	{
		eaName.Buffer = ea->EaName;
		eaName.MaximumLength = ea->EaNameLength;
		eaName.Length = ea->EaNameLength;

		eaValue.Buffer = (PCHAR)(ea->EaName+ ea->EaNameLength + 1);
		eaValue.MaximumLength = ea->EaValueLength;
		eaValue.Length = ea->EaValueLength;

		if (!RtlCompareString(&s_HashAtrributeName,&eaName,TRUE))
		{
			encodedHash->Length = 0;
			encodedHash->MaximumLength = ea->EaValueLength * sizeof(WCHAR) + sizeof(WCHAR);
			encodedHash->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, encodedHash->MaximumLength, TAG_WARDEN);
			if (!encodedHash->Buffer)
			{
				DbgPrint(__FUNCTION__": "" ExAllocatePoolWithTag returns NULL");
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto end;
			}
			status = RtlAnsiStringToUnicodeString(encodedHash, &eaValue, TRUE);
			if (!NT_SUCCESS(status))
			{
				DbgPrint(__FUNCTION__": "" RtlAnsiStringToUnicodeString returns= %0x \n", status);
				goto end;
			}
			break;
		}
		if (!ea->NextEntryOffset)
			break;
		ea = (PFILE_FULL_EA_INFORMATION)((PUCHAR)ea + ea->NextEntryOffset);
	}
	status = STATUS_SUCCESS;
end:
	if (!eaBuff)
	{
		ExFreePoolWithTag(eaBuff, TAG_WARDEN);
	}
	return status;
}

BOOLEAN VerifyHash(FILE_OBJECT* fileObject)
{
	HANDLE fileHandle = NULL;
	UNICODE_STRING exAttrHash = { 0 , };
	UNICODE_STRING fileHash = { 0 , };
	BOOLEAN isVerified = FALSE;
	NTSTATUS status = ObOpenObjectByPointer(fileObject,
		OBJ_KERNEL_HANDLE,
		NULL,
		GENERIC_READ,
		*IoFileObjectType,
		KernelMode,
		&fileHandle);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" ObOpenObjectByPointer = %0x \n", status);
		goto end;
	}
	status = QueryHashEaAtrrib(fileHandle, &exAttrHash);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" QueryHashEaAtrrib = %0x \n", status);
		goto end;
	}


	status = CalculateFileHash(fileHandle, &fileHash);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" CalculateFileHash = %0x \n", status);
		goto end;
	}
	DbgPrint(__FUNCTION__":"" HASH readfrom EA = [%wZ] \n", &exAttrHash);
	DbgPrint(__FUNCTION__":"" HASH calculated  = [%wZ] \n", &fileHash);
	if (!RtlCompareUnicodeString(&exAttrHash, &fileHash, FALSE))
	{
		DbgPrint(__FUNCTION__":"" Signature Verified !!!!!  \n");
		isVerified = TRUE;
	}
	else
	{
		DbgPrint(__FUNCTION__":"" FAILED to Verify Signature \n");

	}
end:
	if (exAttrHash.Buffer)
		ExFreePoolWithTag(exAttrHash.Buffer, TAG_WARDEN);
	if (fileHash.Buffer)
		ExFreePoolWithTag(fileHash.Buffer, TAG_WARDEN);
	if (fileHandle)
		ZwClose(fileHandle);
	return isVerified;
}

VOID
WardenCreateProcessCB(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo != NULL)
	{
		if (!VerifyHash(CreateInfo->FileObject))
		{
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}

	}
}


NTSTATUS
SysDestroy(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "sysDestroy\n");
	if (s_bCryptoInitialized)
	{
		BCryptCloseAlgorithmProvider(s_HashAlgoHandle, 0);
		s_bCryptoInitialized = FALSE;
	}

	if (s_bProcessCBRegisterd)
	{
		status = PsSetCreateProcessNotifyRoutineEx(WardenCreateProcessCB, TRUE);
		s_bProcessCBRegisterd = FALSE;

	}

	if (s_bDosDevLinkCreated)
	{
		status = IoDeleteSymbolicLink(&s_WardenDosLinkName);
		s_bDosDevLinkCreated = FALSE;
	}

	if (s_bNtDeviceCreated)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
		s_bNtDeviceCreated = FALSE;
	}

	return status;
}
NTSTATUS
sysUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

	This is the unload routine for this miniFilter driver. This is called
	when the minifilter is about to be unloaded. We can fail this unload
	request if this is not a mandatory unload indicated by the Flags
	parameter.

Arguments:

	Flags - Indicating if this is a mandatory unload.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{

	PAGED_CODE();

	SysDestroy(DriverObject);
	return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Routine can return non success error codes.

--*/
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	//Create Device
	status = IoCreateDevice(DriverObject, 0, &s_WardenNtDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" IoCreateDevice = %0x \n", status);
		goto end;
	}
	DriverObject->DriverUnload = sysUnload;
	s_bNtDeviceCreated = TRUE;

	// Create a link in the Win32 namespace.
	status = IoCreateSymbolicLink(&s_WardenDosLinkName, &s_WardenNtDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" IoCreateSymbolicLink = %0x \n", status);
		goto end;
	}
	s_bDosDevLinkCreated = TRUE;

	status = PsSetCreateProcessNotifyRoutineEx(WardenCreateProcessCB, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" PsSetCreateProcessNotifyRoutineEx  = %0x \n", status);
		goto end;
	}
	s_bProcessCBRegisterd = TRUE;

	status = InitilizeCrypto();
	if (!NT_SUCCESS(status))
	{
		DbgPrint(__FUNCTION__":"" InitilizeCrypto = %0x \n", status);
		goto end;
	}
	s_bCryptoInitialized = TRUE;
end:

	if (!NT_SUCCESS(status))
	{
		SysDestroy(DriverObject);
	}

	return status;
}