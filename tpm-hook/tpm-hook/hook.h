#pragma once

namespace Hook
{
	extern PDRIVER_DISPATCH originalDispatch;
	extern TPM2B_PUBLIC_KEY_RSA generatedKey;

	NTSTATUS HandleReadPublic(PDEVICE_OBJECT device, PIRP irp, PVOID context);
	NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp);
}
