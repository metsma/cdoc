#include "DDOCReader.h"

#include "XMLReader.h"

std::vector<DDOCReader::File> DDOCReader::files(const std::vector<unsigned char> &data)
{
	XMLReader reader(data);
	std::vector<DDOCReader::File> result;
	while(reader.read())
	{
		if(reader.isEndElement())
			continue;
		// EncryptedData
		if(!reader.isElement("DataFile"))
			continue;
		result.push_back({
			reader.attribute("Filename"),
			reader.attribute("MimeType"),
			reader.readBase64()
		});
	}
	return result;
}
