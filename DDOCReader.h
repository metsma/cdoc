#pragma once

#include <string>
#include <vector>

class DDOCReader
{
public:
	struct File
	{
		std::string name, mime;
		std::vector<unsigned char> data;
	};
	static std::vector<File> files(const std::vector<unsigned char> &data);
};
