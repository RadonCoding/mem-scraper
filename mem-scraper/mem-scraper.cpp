#include "mem-scraper.hpp"
#include <iostream>
#include <vector>
#include <TlHelp32.h>
#include <set>
#include <string>

DWORD g_stack[MAX_STACK_SIZE];
std::set<std::string> g_strings;

std::vector<DWORD> getProcessesByName(std::string name)
{
	PROCESSENTRY32 entry;
	ZeroMemory(&entry, sizeof(PROCESSENTRY32));
	entry.dwSize = sizeof(PROCESSENTRY32);

	std::vector<DWORD> processes;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry) == TRUE)
	{
		while (Process32Next(hSnapshot, &entry) == TRUE)
		{
			if (entry.szExeFile == name)
			{
				processes.push_back(entry.th32ProcessID);
			}
		}
	}

	CloseHandle(hSnapshot);

	return processes;
}

SYSTEM_PROCESS_INFORMATION *getProcessInfo()
{
	ULONG returnLength;

	if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &returnLength)))
	{
		void *buffer = malloc(returnLength);

		if (!buffer)
		{
			return nullptr;
		}

		SYSTEM_PROCESS_INFORMATION *spi = (SYSTEM_PROCESS_INFORMATION *)buffer;

		if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, returnLength, NULL)))
		{
			free(buffer);
			return nullptr;
		}
		return spi;
	}
	return nullptr;
}

bool checkAnsiString(BYTE *pStackValue, char *szString)
{
	DWORD dwNullPos = 0;
	DWORD dwStringLength = 0;

	for (DWORD i = 0; i < MAX_VALUE_SIZE; i++)
	{
		char c = *(BYTE *)(pStackValue + i);

		if (c == 0x00)
		{
			dwNullPos = i;
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n'))
		{
			return false;
		}
		else
		{
			dwStringLength++;
		}
	}

	if (dwNullPos == 0 || dwStringLength == 0)
	{
		return false;
	}
	memcpy(szString, pStackValue, dwStringLength);

	return true;
}

bool checkWideString(BYTE *pStackValue, char *szString)
{
	DWORD dwNullPos = 0;
	DWORD dwStringLength = 0;

	for (DWORD i = 0; i < MAX_VALUE_SIZE; i++)
	{
		char c = *(BYTE *)(pStackValue + i);

		if (i % 2 == 1)
		{
			if (c != 0x00)
			{
				return false;
			}
			continue;
		}

		if (c == 0x00)
		{
			dwNullPos = i;
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n'))
		{
			return false;
		}
		else
		{
			dwStringLength++;
		}
	}

	if (dwNullPos == 0 || dwStringLength == 0)
	{
		return false;
	}
	memcpy(szString, pStackValue, dwStringLength);

	return true;
}

bool checkValidString(char *szString)
{
	DWORD dwLength = strlen(szString);

	if (dwLength < 5)
	{
		return false;
	}

	// These checks are to avoid "bloat"
	if (dwLength < 8)
	{
		for (DWORD i = 0; i < dwLength; i++)
		{
			BYTE c = *(BYTE *)(szString + i);

			if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9')
			{
				continue;
			}
			return false;
		}
	}
	return true;
}

void processString(BYTE *pData, DWORD *pdwStringLength, std::string filter, StringSource source)
{
	char szString[MAX_VALUE_SIZE];
	ZeroMemory(szString, sizeof(szString));

	if (!checkAnsiString(pData, szString))
	{
		if (!checkWideString(pData, szString))
		{
			return;
		}
	}

	if (!checkValidString(szString))
	{
		return;
	}

	for (int i = 0; i < strlen(szString); i++)
	{
		if (szString[i] == '\r' || szString[i] == '\n')
		{
			szString[i] = '.';
		}
	}

	std::string str = std::string(szString);

	if (pdwStringLength)
	{
		*pdwStringLength = str.length();
	}

	if (!g_strings.contains(str))
	{
		if (!filter.empty() && str.find(filter) == std::string::npos)
		{
			return;
		}

		switch (source)
		{
		case StringSource::STACK:
			std::cout << "Found stack string: " << str << std::endl;
			break;
		case StringSource::HEAP:
			std::cout << "Found heap string: " << str << std::endl;
			break;
		}
		g_strings.insert(str);
	}
}

void findLocalStrings(DWORD dwStackSize, std::string filter)
{
	DWORD *dwCurrentStackValue = g_stack;

	for (DWORD i = 0; i < dwStackSize; i++)
	{
		if (*dwCurrentStackValue == 0x00)
		{
			dwCurrentStackValue++;
			continue;
		}

		BYTE pStackValue[MAX_VALUE_SIZE];

		DWORD dwCopyLength = sizeof(g_stack) - i;

		if (dwCopyLength > sizeof(pStackValue))
		{
			dwCopyLength = sizeof(pStackValue);
		}

		ZeroMemory(pStackValue, sizeof(pStackValue));
		memcpy(pStackValue, dwCurrentStackValue, dwCopyLength);

		DWORD dwStringLength = 0;
		processString(pStackValue, &dwStringLength, filter, StringSource::STACK);

		if (dwStringLength != 0)
		{
			dwCurrentStackValue += dwStringLength;
		}
		else
		{
			dwCurrentStackValue++;
		}
	}
}

void findPointerStrings(HANDLE hProcess, DWORD dwStackSize, std::string filter)
{
	DWORD *dwCurrentStackValue = g_stack;

	for (DWORD i = 0; i < (dwStackSize / sizeof(DWORD)); i++)
	{
		// Potential data pointer

		if (*dwCurrentStackValue >= 0x10000)
		{
			BYTE pStackValue[MAX_VALUE_SIZE];
			ZeroMemory(&pStackValue, sizeof(pStackValue));

			if (ReadProcessMemory(hProcess, dwCurrentStackValue, pStackValue, sizeof(pStackValue), 0))
			{
				processString(pStackValue, nullptr, filter, StringSource::STACK);
			}
		}
		dwCurrentStackValue++;
	}
}

void getStackStrings(HANDLE hProcess, HANDLE hThread, std::string filter)
{
	THREAD_BASIC_INFORMATION tbi;
	ZeroMemory(&tbi, sizeof(tbi));

	if (!NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)))
	{
		return;
	}

	NT_TIB teb;
	ZeroMemory(&teb, sizeof(teb));

	if (!ReadProcessMemory(hProcess, tbi.TebBaseAddress, &teb, sizeof(teb), 0))
	{
		return;
	}

	intptr_t dwStackSize = (intptr_t)teb.StackBase - (intptr_t)teb.StackLimit;

	if (dwStackSize > sizeof(g_stack))
	{
		return;
	}

	ZeroMemory(g_stack, sizeof(g_stack));

	if (!ReadProcessMemory(hProcess, teb.StackLimit, g_stack, dwStackSize, 0))
	{
		return;
	}

	findPointerStrings(hProcess, dwStackSize, filter);
	findLocalStrings(dwStackSize, filter);
}

void getHeapStrings(HANDLE hProcess, std::string filter)
{
	MEMORY_BASIC_INFORMATION mbi;

	// Loop all the memory pages and search contents for strings
	for (BYTE *address = nullptr; VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi); address += mbi.RegionSize)
	{
		if (mbi.State != MEM_COMMIT)
		{
			continue;
		}
		if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
		{
			continue;
		}

		if (mbi.Type != MEM_MAPPED && mbi.Type != MEM_PRIVATE)
		{
			continue;
		}

		std::vector<BYTE> page(mbi.RegionSize);

		if (!ReadProcessMemory(hProcess, mbi.BaseAddress, page.data(), page.capacity(), nullptr))
		{
			continue;
		}

		for (size_t i = 0; i < page.size(); i++)
		{
			if (page[i] == 0x00)
			{
				continue;
			}

			BYTE pHeapValue[MAX_VALUE_SIZE];

			DWORD dwCopyLength = page.size() - i;

			if (dwCopyLength > sizeof(pHeapValue))
			{
				dwCopyLength = sizeof(pHeapValue);
			}

			ZeroMemory(pHeapValue, sizeof(pHeapValue));
			memcpy(pHeapValue, &page[i], dwCopyLength);

			DWORD dwStringLength = 0;
			processString(pHeapValue, &dwStringLength, filter, StringSource::HEAP);

			if (dwStringLength != 0)
			{
				i += dwStringLength;
			}
		}
	}
}

void scanProcess(DWORD dwProcId, std::string filter)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwProcId);

	getHeapStrings(hProcess, filter);

	SYSTEM_PROCESS_INFORMATION *spi = getProcessInfo();

	if (!spi)
	{
		return;
	}

	while ((intptr_t)spi->UniqueProcessId != dwProcId)
	{
		if (!spi->NextEntryOffset)
		{
			return;
		}
		spi = (SYSTEM_PROCESS_INFORMATION *)((BYTE *)spi + spi->NextEntryOffset);
	}

	SYSTEM_THREAD_INFORMATION *sti = (SYSTEM_THREAD_INFORMATION *)((BYTE *)spi + sizeof(SYSTEM_PROCESS_INFORMATION));

	for (int i = 0; i < spi->NumberOfThreads; i++)
	{
		HANDLE hThread = nullptr;

		OBJECT_ATTRIBUTES objectAttributes;
		ZeroMemory(&objectAttributes, sizeof(objectAttributes));
		objectAttributes.Length = sizeof(objectAttributes);

		DWORD dwStatus = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &objectAttributes, &sti->ClientId);

		if (dwStatus == 0)
		{
			getStackStrings(hProcess, hThread, filter);
			CloseHandle(hThread);
		}
		sti++;
	}
	CloseHandle(hProcess);
}

int main()
{
	std::cout << "Enter filter (default = none): ";

	std::string filter;
	std::getline(std::cin, filter);

	std::cout << "Enter process name: ";

	std::string processName;
	std::cin >> processName;

	std::vector<DWORD> processes = getProcessesByName(processName);

	if (processes.empty())
	{
		std::cout << "No process with that name was found!" << std::endl;
		return EXIT_FAILURE;
	}

	while (true)
	{
		for (DWORD dwProcId : processes)
		{
			scanProcess(dwProcId, filter);
		}
	}
	return EXIT_SUCCESS;
}