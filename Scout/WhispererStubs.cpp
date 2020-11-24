#include "WhispererStubs.h"
#include "Utilities.h"


void RetrieveDefaultStubs(unsigned char **DecryptOut, unsigned long *DecryptLength) {
	DecryptionStub<0x88, 0x99> Stub;

	*DecryptLength = Stub.len();
	*DecryptOut = new unsigned char[*DecryptLength];
	Utils::memcpy(*DecryptOut, Stub.decrypt(), *DecryptLength);

};
