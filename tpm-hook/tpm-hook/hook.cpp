#include <stddef.h>

#include "global.h"

TPM2B_PUBLIC_KEY_RSA Hook::generatedKey = { 0 };
NTSTATUS Hook::HandleReadPublic(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(irp);

	Log("Handling TPM_CC_ReadPublic request");

	if (!context)
		return STATUS_SUCCESS;

	Utils::IOC_REQUEST request = *static_cast<Utils::PIOC_REQUEST>(context);
	ExFreePool(context);

	TPM_DATA_READ_PUBLIC* data = static_cast<TPM_DATA_READ_PUBLIC*>(request.Buffer);

	const UINT32 commandSize = Utils::BigEndianToLittleEndian32(data->Header.paramSize);
	const size_t keySize = 128;
	const size_t minSize = offsetof(TPM_DATA_READ_PUBLIC, OutPublic.publicArea.unique.rsa.buffer) + keySize;
	if (commandSize < minSize)
	{
		Log("Ignoring, too small");
		return STATUS_SUCCESS;
	}

	memcpy(data->OutPublic.publicArea.unique.rsa.buffer, generatedKey.buffer, keySize);

	Log("Changed %u bytes of EK data", keySize);

	return STATUS_SUCCESS;
}

PDRIVER_DISPATCH Hook::originalDispatch = nullptr;
NTSTATUS Hook::Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
	Log("Hook called from 0x%p", _ReturnAddress());

	const PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_TPM_SUBMIT_COMMAND)
	{
		const TPM2_COMMAND_HEADER* header = static_cast<TPM2_COMMAND_HEADER*>(irp->AssociatedIrp.SystemBuffer);
		const TPM_CC command = Utils::BigEndianToLittleEndian32(header->commandCode);
		if (command == TPM_CC_ReadPublic)
			Utils::ChangeIoc(ioc, irp, &HandleReadPublic);
	}

	return originalDispatch(device, irp);
}