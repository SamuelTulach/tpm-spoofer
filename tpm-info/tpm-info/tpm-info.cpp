#include "global.h"

int main()
{
	std::vector<BYTE> ekData = Utils::GetEK();
	if (ekData.empty())
	{
		printf("Failed to retrieve EK\n");
		return EXIT_FAILURE;
	}

	printf("MD5:     %s\n", Utils::GetKeyHash(ekData, CALG_MD5).c_str());
	printf("SHA1:    %s\n", Utils::GetKeyHash(ekData, CALG_SHA1).c_str());
	printf("SHA256:  %s\n", Utils::GetKeyHash(ekData, CALG_SHA_256).c_str());

	return EXIT_SUCCESS;
}