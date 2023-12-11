#include "global.h"

EXTERN_C NTSTATUS Entry()
{
	Log("Entry at 0x%p", &Entry);

	NTSTATUS status = Utils::GenerateRandomKey(&Hook::generatedKey);
	if (!NT_SUCCESS(status))
	{
		Log("Failed to generate random key");
		return status;
	}

	UNICODE_STRING driverName;
	RtlInitUnicodeString(&driverName, L"\\Driver\\TPM");

	PDRIVER_OBJECT driverObject;
	status = Utils::ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
		*Utils::IoDriverObjectType, KernelMode, nullptr,
		reinterpret_cast<PVOID*>(&driverObject));
	if (!NT_SUCCESS(status))
		return status;

	Log("Found tpm.sys DRIVER_OBJECT at 0x%p", driverObject);

	/*
	 * Everything is pointing to Wdf01000!FxDevice::DispatchWithLock
	 */
	Hook::originalDispatch = driverObject->MajorFunction[0];

	for (DWORD i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		driverObject->MajorFunction[i] = &Hook::Dispatch;

	Log("Dispatch hooked");

	return STATUS_SUCCESS;
}