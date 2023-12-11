#pragma once

#pragma pack(push, 1)
// Page 71
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
typedef struct _TPM_DATA
{
	TPM2_RESPONSE_HEADER Header;
	TPM2B_PUBLIC OutPublic;
	TPM2B_NAME Name;
	TPM2B_NAME QualifiedName;
} TPM_DATA;
#pragma pack(pop)