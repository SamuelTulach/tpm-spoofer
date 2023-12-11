#pragma once

namespace Utils
{
	std::string BytesToString(const std::vector<BYTE>& bytes);
	std::vector<BYTE> GetEK();
	std::string GetKeyHash(const std::vector<BYTE>& input, ALG_ID algo);
}