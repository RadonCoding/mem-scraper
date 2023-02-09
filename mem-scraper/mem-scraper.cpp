#include "mem-scraper.hpp"
#include <TlHelp32.h>
#include <set>
#include <chrono>
#include <regex>
#include <fstream>

std::fstream g_cacheFile(CACHE_PATH, std::ios::in | std::ios::out | std::ios::trunc);

bool isANSIString(std::string szString)
{
	for (size_t i = 0; i < szString.length(); i++)
	{
		char c = szString[i];

		if (c == 0x00)
		{
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n'))
		{
			return false;
		}
	}
	return true;
}

bool isWideString(std::string szString)
{
	for (size_t i = 0; i < szString.length(); i++)
	{
		char c = szString[i];

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
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n'))
		{
			return false;
		}
	}
	return true;
}

bool isCached(std::string szString) {
	if (!g_cacheFile.is_open())
	{
		std::cout << "Failed to open cache file!" << std::endl;
		exit(EXIT_FAILURE);
	}

	g_cacheFile.seekg(0, std::ios::beg);

	std::string line;

	while (std::getline(g_cacheFile, line))
	{
		if (line == szString)
		{
			return true;
		}
	}
	g_cacheFile.clear();
	g_cacheFile.seekp(0, std::ios::end);
	g_cacheFile << szString << std::endl;
	return false;
}

void processString(std::vector<char> data, size_t* pdwStringLength, std::string filter, StringSource source)
{
	size_t dwNullPos = 0;

	for (size_t i = 0; i < data.size(); i++)
	{
		if (data[i] == '\0')
		{
			dwNullPos = i;
			break;
		}
	}

	if (!dwNullPos)
	{
		return;
	}

	std::string szString(&data[0], dwNullPos);

	szString.erase(0, szString.find_first_not_of(' '));

	if (szString.empty()) {
		return;
	}

	if (!isANSIString(szString) && !isWideString(szString))
	{
		return;
	}

	if (pdwStringLength)
	{
		*pdwStringLength = szString.length();
	}

	if (szString.length() - 1 <= 5) {
		return;
	}

	// Replace line breaks with a dot for ease of printing
	for (int i = 0; i < szString.length(); i++)
	{
		if (szString[i] == '\r' || szString[i] == '\n')
		{
			szString[i] = '.';
		}
	}

	if (isCached(szString))
	{
		return;
	}

	std::smatch match;

	if (!filter.empty() && !std::regex_search(szString, match, std::regex(filter)))
	{
		return;
	}

	switch (source)
	{
	case StringSource::LOCAL:
		std::cout << "Found local string: " << szString << std::endl;
		break;
	case StringSource::POINTER:
		std::cout << "Found pointer string: " << szString << std::endl;
		break;
	case StringSource::HEAP:
		std::cout << "Found heap string: " << szString << std::endl;
		break;
	}
}

// Finds values from the stack that are raw values
void findLocalStrings(std::vector<intptr_t> stack, std::string filter)
{
	for (size_t i = 0; i < stack.size(); i++)
	{
		if (stack[i] == '\0')
		{
			continue;
		}

		size_t dwCopyLength = stack.size() - i;

		if (dwCopyLength > MAX_VALUE_SIZE)
		{
			dwCopyLength = MAX_VALUE_SIZE;
		}

		std::vector<char> stackValue(dwCopyLength);
		memcpy(&stackValue[0], &stack[i], stackValue.capacity());

		size_t dwStringLength = 0;
		processString(stackValue, &dwStringLength, filter, StringSource::LOCAL);

		if (dwStringLength != 0)
		{
			i += dwStringLength;
		}
	}
}

// Finds values from the stack that are pointers and then reads the values
void findPointerStrings(std::vector<intptr_t> stack, std::string filter, HANDLE hProcess)
{
	for (size_t i = 0; i < (stack.size() / sizeof(&stack[0])); i++)
	{
		if (stack[i] == '\0')
		{
			continue;
		}

		std::vector<char> stackValue(MAX_VALUE_SIZE);

		if (ReadProcessMemory(hProcess, (intptr_t*)stack[i], &stackValue[0], stackValue.capacity(), nullptr))
		{
			processString(stackValue, nullptr, filter, StringSource::POINTER);
		}
	}
}

// Initializes the stack and calls the string capture functions
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

	std::vector<intptr_t> stack(dwStackSize);

	if (!ReadProcessMemory(hProcess, teb.StackLimit, stack.data(), stack.capacity(), nullptr))
	{
		return;
	}

	findPointerStrings(stack, filter, hProcess);
	findLocalStrings(stack, filter);
}

// Finds strings from the process heap
void getHeapStrings(HANDLE hProcess, std::string filter)
{
	MEMORY_BASIC_INFORMATION mbi;

	// Loop all the memory pages and search contents for strings
	for (char* address = nullptr; VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)); address += mbi.RegionSize)
	{
		if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_EXECUTE)))
		{
			continue;
		}

		std::vector<char> page(mbi.RegionSize);

		if (!ReadProcessMemory(hProcess, mbi.BaseAddress, &page[0], page.capacity(), nullptr))
		{
			continue;
		}

		for (size_t i = 0; i < page.size(); i++)
		{
			if (page[i] == '\0')
			{
				continue;
			}

			size_t dwCopyLength = page.size() - i;

			if (dwCopyLength > MAX_VALUE_SIZE)
			{
				dwCopyLength = MAX_VALUE_SIZE;
			}

			std::vector<char> heapValue(dwCopyLength);
			memcpy(&heapValue[0], &page[i], heapValue.capacity());

			size_t dwStringLength = 0;
			processString(heapValue, &dwStringLength, filter, StringSource::HEAP);

			if (dwStringLength != 0)
			{
				i += dwStringLength;
			}
		}
	}
}

// Gets the system information for all processes in the system
SYSTEM_PROCESS_INFORMATION* getSystemProcessInformation() {
	ULONG returnLength;
	NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &returnLength)
		
	void* buffer = malloc(returnLength);

	if (!buffer)
	{
		std::cout << std::format("Failed to allocate {} bytes of memory!", returnLength) << std::endl;
		return nullptr;
	}

	SYSTEM_PROCESS_INFORMATION* spi = (SYSTEM_PROCESS_INFORMATION*)buffer;

	if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, returnLength, nullptr)))
	{
		free(buffer);
		// Stack overflow potential but i don't care
		return getSystemProcessInformation();
	}
	return spi;
}

bool scanProcess(DWORD dwProcId, std::string filter, int target)
{
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwProcId);

	if (!hProcess) {
		std::cout << "Failed to find the process!" << std::endl;
		return false;
	}

	if (target == 0 || target == 1) {
		getHeapStrings(hProcess, filter);
	}

	if (target == 0 || target == 2) {

		SYSTEM_PROCESS_INFORMATION* spi = getSystemProcessInformation();
	
		if (!spi)
		{
			return false;
		}

		// Loop until the current entry is the target process
		while ((intptr_t)spi->UniqueProcessId != dwProcId)
		{
			if (!spi->NextEntryOffset)
			{
				std::cout << "Failed to find the process!" << std::endl;
				return false;
			}
			spi = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
		}

		// The thread information is at the end of SYSTEN_PROCESS_INFORMATION
		SYSTEM_THREAD_INFORMATION* sti = (SYSTEM_THREAD_INFORMATION*)((BYTE*)spi + sizeof(SYSTEM_PROCESS_INFORMATION));

		// Loop all the threads and capture the strings from the stack
		for (DWORD i = 0; i < spi->NumberOfThreads; i++)
		{
			HANDLE hThread = nullptr;

			OBJECT_ATTRIBUTES objectAttributes;
			ZeroMemory(&objectAttributes, sizeof(objectAttributes));
			objectAttributes.Length = sizeof(objectAttributes);

			// We use NtOpenThread so we can pass the CLIENT_ID which OpenThread can't do
			DWORD dwStatus = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &objectAttributes, &sti->ClientId);

			if (dwStatus == 0)
			{
				getStackStrings(hProcess, hThread, filter);
				CloseHandle(hThread);
			}
			sti++;
		}
	}

	CloseHandle(hProcess);

	return true;
}

DWORD getProcessByName(std::string name) {
	PROCESSENTRY32 entry;
	ZeroMemory(&entry, sizeof(PROCESSENTRY32));
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	DWORD pid = 0;

	if (Process32First(hSnapshot, &entry) == TRUE)
	{
		while (Process32Next(hSnapshot, &entry) == TRUE)
		{
			if (entry.szExeFile == name)
			{
				pid = entry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(hSnapshot);

	return pid;
}

int main(int argc, char** argv) {
	InputParser input(argc, argv);
	input.parse();

	if (input.contains("help")) {
		input.usage();
	}

	std::string filter;
	input.get("filter", &filter);

	DWORD pid = 0;
	input.get("pid", &pid);

	std::string name;

	if (input.get("name", &name)) {
		pid = getProcessByName(name);

		if (!pid) {
			std::cout << "Could not find the process!" << std::endl;
			return EXIT_FAILURE;
		}
	}

	if (!pid) {
		input.usage();
		return EXIT_FAILURE;
	}

	int target = 0;
	input.get("target", &target);

	DWORD delay = 1000;
	input.get("delay", &delay);

	while (scanProcess(pid, filter, target))
	{
		Sleep(delay);
	}

	g_cacheFile.close();

	return EXIT_SUCCESS;
}
