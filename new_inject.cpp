#include <stdio.h>
#include <stdlib.h>

typedef PVOID(WINAPI *PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);

int main()
{
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");	
	PVirtualAlloc funcVirtualAlloc = (PVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
	
	
	return 0;
}