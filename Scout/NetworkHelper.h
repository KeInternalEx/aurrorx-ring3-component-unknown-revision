#ifndef __NETWORK_HELPER_
#define __NETWORK_HELPER_

#ifndef __HOST_BLOCK_
#include "HostBlock.h"
#endif

#ifndef __UTILITIES_
#include "Utilities.h"
#endif

#ifndef __WHISPERER_STUBS_
#include "WhispererStubs.h"
#endif

#ifndef _VECTOR_
#include <vector>
#endif

typedef struct _IP_CACHE {
	char *Host;
	char *IpAddress;
	
	unsigned char HostLength;
	unsigned char IpLength;
} IP_CACHE, *PIP_CACHE;

class NetworkHelpers {
private:
	WhispererHostBlock *HostBlock;
	std::vector<PIP_CACHE> CacheVector;

	char *GetFormat() {
		return 
			"GET %s HTTP/1.1\r\n"
			"User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
			"Host: %s\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";
	};
	char *PostFormat() {
		return  
			"POST %s HTTP/1.1\r\n"
			"User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n"
			"Host: %s\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Length: %d\r\n"
			"\r\n";
	};

	unsigned short GetLength() { return 112; };
	unsigned short PostLength() { return 134; };

public:
	NetworkHelpers(WhispererHostBlock *pHostBlock);
	~NetworkHelpers();

	void UpdateHostBlock(WhispererHostBlock *pHostBlock);
	bool CrackUrl(char *Url, char **HostOut, char **PathOut);
	unsigned long IpV4ToBin(char *Ip);
	unsigned char *IpV6ToBin(char *Ip);
	unsigned char *BinToIpV4(unsigned long Ip, bool LittleEndian);
	unsigned char *BinToIpV6(unsigned char Ip[16], bool LittleEndian);
	unsigned char *HostToAddress(char *Host, bool *AddressType);
	char *CreateHttpRequest(char *Type, char *Host, char *Path, char *Body, unsigned long BodyLength, unsigned long *LengthOut);
};


#endif
