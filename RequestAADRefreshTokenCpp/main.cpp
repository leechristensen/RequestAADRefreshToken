#include <stdio.h>
#include <proofofpossessioncookieinfo.h>
#include <windows.h>

// compile with Visual Studio or clang -lole32 -s main.cpp -o requestaadrefreshtoken.exe

#define BUFSIZE 2048

int main()
{
	wchar_t uri[2048];
	DWORD cookieCount = 0;
	ProofOfPossessionCookieInfo* cookies;
	IProofOfPossessionCookieInfoManager* popCookieManager;
	GUID CLSID_ProofOfPossessionCookieInfoManager;
	GUID IID_IProofOfPossessionCookieInfoManager;

	CLSIDFromString(L"{A9927F85-A304-4390-8B23-A75F1C668600}", &CLSID_ProofOfPossessionCookieInfoManager);
	IIDFromString(L"{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}", &IID_IProofOfPossessionCookieInfoManager);

	memset(uri, 0x00, sizeof(uri));

	if ( argc < 2) {
		_snwprintf_s(uri, BUFSIZE, BUFSIZE, L"%ls", L"https://login.microsoftonline.com/common/oauth2/authorize");
	} else {
		mbstowcs(uri, argv[1], BUFSIZE);
	}

	wprintf(L"Using URI: %ls\n", uri);

	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr))
	{
		wprintf(L"CoInitialize error: %d\n", hr);;
		return 0;
	}

	hr = CoCreateInstance(CLSID_ProofOfPossessionCookieInfoManager, NULL, CLSCTX_INPROC_SERVER, IID_IProofOfPossessionCookieInfoManager, reinterpret_cast<void**>(&popCookieManager));
	if (FAILED(hr))
	{
		wprintf(L"CoCreateInstance error: %d\n", hr);;
		return 0;
	}


	hr = popCookieManager->GetCookieInfoForUri(uri, &cookieCount, &cookies);
	if (FAILED(hr))
	{
		wprintf(L"GetCookieInfoForUri error: %d\n", hr);
		return 0;
	}

	if (cookieCount == 0)
	{
		wprintf(L"No cookies for the URI: %ls\n", uri);
		return 0;
	}

	for (DWORD i = 0; i < cookieCount; i++)
	{
		wprintf(L"Name: %ls\n", cookies[i].name);
		wprintf(L"Data: %ls\n", cookies[i].data);
		wprintf(L"Flags: %x\n", cookies[i].flags);
		wprintf(L"P3PHeader: %ls\n\n", cookies[i].p3pHeader);
	}

	FreeProofOfPossessionCookieInfoArray(cookies, cookieCount);

	printf("DONE\n");

	return 0;
}
