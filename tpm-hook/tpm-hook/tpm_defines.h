#pragma once

#define IOCTL_TPM_SUBMIT_COMMAND 0x22C00C

#pragma pack(push, 1)
// Page 71
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
typedef struct _TPM_DATA_READ_PUBLIC
{
	TPM2_RESPONSE_HEADER Header;
	TPM2B_PUBLIC OutPublic;
} TPM_DATA_READ_PUBLIC;
#pragma pack(pop)