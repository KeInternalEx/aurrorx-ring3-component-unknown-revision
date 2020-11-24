#ifndef __META_
#define __META_

#pragma region Obfuscation

#define MetaBlockCallOperation(Operand) ((((((((Operand) + 0x9c899ffa) ^ 10) - 0x80fc3ceb) ^ 0x30) + 0x913f) - 3 ) ^ 0xff381900) 

class MetaBlockCall {
private:
	const unsigned long FunctionAddress;

public:
	constexpr const MetaBlockCall(unsigned long Address) :
		FunctionAddress( MetaBlockCallOperation(Address) )
	{ };

	unsigned long DecodePointer() {
		return (((((((((this->FunctionAddress ) ^ 0xff381900) + 3) - 0x913f) ^ 0x30) + 0x80fc3ceb) ^ 10) - 0x9c899ffa) + (*((UCHAR*)__readfsdword(0x30) + 2) * 0x84));
	};
};

#pragma endregion

#pragma region Randomization

#pragma endregion

#pragma region Index List

template <unsigned long... Pack> struct IndexList {};
template <typename IndexList, unsigned long Right> struct Append;
template <unsigned long... Left, unsigned long Right> struct Append<IndexList<Left...>, Right> {
	typedef IndexList<Left..., Right> Result;
};
template <unsigned long N> struct ConstructIndexList {
	typedef typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result Result;
};
template <> struct ConstructIndexList<0> {
	typedef IndexList<> Result;
};


#pragma endregion

#pragma region Encryption

#define MetaXorKeyDefaultA      "0x0rKeY800"
#define MetaXorKeyDefaultW     L"0x0rKeY800"


constexpr char MetaEncryptCharacterA(const char XorKey, const char Character, unsigned char Index) {
	return Character ^ (XorKey + Index);
};
constexpr wchar_t MetaEncryptCharacterW(const wchar_t XorKey, const wchar_t Character, unsigned char Index) {
	return Character ^ (XorKey + Index);
};

template <unsigned short KeyLength, typename IndexList> class MetaXorStringW;
template <unsigned short KeyLength, unsigned long... Index> class MetaXorStringW<KeyLength, IndexList<Index...>> {
private:
	wchar_t Value[sizeof...(Index)+1];
public:
	constexpr MetaXorStringW(const wchar_t * const String, const wchar_t * const Key)
		: Value { MetaEncryptCharacterW(Key[Index % KeyLength], String[Index], Index & 0xff)... } {};

	wchar_t *Decrypt(wchar_t *Key) {
		for (unsigned long i = 0; i < sizeof...(Index); i++) 
			Value[i] ^= (Key[i % KeyLength] + ((i * (1 + *((UCHAR*)__readfsdword(0x30) + 2))) & 0xff));
		
		Value[sizeof...(Index)] = 0;
		return Value;
	};
};

template <unsigned long KeyLength, typename IndexList> class MetaXorStringA;
template <unsigned long KeyLength, unsigned long... Index> class MetaXorStringA<KeyLength, IndexList<Index...>> {
private:
	char Value[sizeof...(Index)+1];
public:
	constexpr MetaXorStringA(const char * const String, const char * const Key)
		: Value{ MetaEncryptCharacterA(Key[Index % KeyLength], String[Index], Index & 0xff)... } {};

	char *Decrypt(char *Key) {
		for (unsigned long i = 0; i < sizeof...(Index); i++)
			Value[i] ^= (Key[i % KeyLength] + ((i * (1 + *((UCHAR*)__readfsdword(0x30) + 2))) & 0xff));

		Value[sizeof...(Index)] = 0;
		return Value;
	};
};


#define EncryptedStringW(String, Key) (MetaXorStringW<(sizeof((Key)) / sizeof((Key)[0])) - 1, ConstructIndexList<(sizeof((String)) / sizeof((String)[0])) - 1>::Result>((String), (Key)).Decrypt((Key)))
#define EncryptedStringA(String, Key) (MetaXorStringA<(sizeof((Key)) / sizeof((Key)[0])) - 1, ConstructIndexList<(sizeof((String)) / sizeof((String)[0])) - 1>::Result>((String), (Key)).Decrypt((Key)))

#define PreKeyedEncryptedStringW(String) (EncryptedStringW((String), (MetaXorKeyDefaultW)))
#define PreKeyedEncryptedStringA(String) (EncryptedStringA((String), (MetaXorKeyDefaultA)))

#pragma endregion


#endif
