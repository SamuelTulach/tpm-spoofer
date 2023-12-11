#include "global.h"

#define IOCTL_TPM_SUBMIT_COMMAND 0x22C00C

TPM2B_PUBLIC_KEY_RSA Hook::generatedKey = { 0 };
NTSTATUS Hook::SubmitCommandIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(irp);

	Log("Handling IOCTL_TPM_SUBMIT_COMMAND");

	if (!context)
		return STATUS_SUCCESS;

	Utils::IOC_REQUEST request = *static_cast<Utils::PIOC_REQUEST>(context);
	ExFreePool(context);

	TPM_DATA* data = static_cast<TPM_DATA*>(request.Buffer);

	UINT32 commandSize = Utils::BigEndianToLittleEndian32(data->Header.paramSize);

	/*
	 * Does not match sizeof(TPM_DATA). Proper way to check this would be to
	 * parse the header also in Hook::Dispatch and check whether the command is
	 * TPM_CC_ReadPublic.
	 */
	if (commandSize != 0x18E)
	{
		Log("Ignoring");
		return STATUS_SUCCESS;
	}

	// UINT32 rsaSize = Utils::BigEndianToLittleEndian16(data->OutPublic.publicArea.unique.rsa.size); // Size in bits

	/*
	 * After very very *very* long debugging session
	 * where I tried everything possible, even dumping different
	 * TPM responses and comparing them, I came to the conclusion that
	 * for some reason unknown to me, if you change the whole key (and it should have 256 bytes)
	 * the TPM stack will just think there was an error. I do not know if I am parsing the
	 * struct wrong or if there is something special about the key, but the 256 byte buffer
	 * matches the registry entry EKPub which is the pure RSA key blob.
	 */
	constexpr SIZE_T keyLength = 100;
	memcpy(data->OutPublic.publicArea.unique.rsa.buffer, generatedKey.buffer, keyLength);

	Log("Changed %u bytes of EK data", keyLength);

	return STATUS_SUCCESS;
}

PDRIVER_DISPATCH Hook::originalDispatch = nullptr;
NTSTATUS Hook::Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
	Log("Hook called from 0x%p", _ReturnAddress());

	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_TPM_SUBMIT_COMMAND:
		Utils::ChangeIoc(ioc, irp, &SubmitCommandIoc);
		break;
	default:
		break;
	}

	return originalDispatch(device, irp);
}