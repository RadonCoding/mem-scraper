#include "mem-scraper.hpp"
#include <TlHelp32.h>
#include <set>
#include <chrono>
#include <regex>
#include <fstream>

std::fstream _cacheFile(CACHE_PATH, std::ios::in | std::ios::out | std::ios::trunc);

bool isANSIString(std::string str) {
	for (size_t i = 0; i < str.length(); i++) {
		char c = str[i];

		if (c == 0x00) {
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n')) {
			return false;
		}
	}
	return true;
}

bool isWideString(std::string str) {
	for (size_t i = 0; i < str.length(); i++) {
		char c = str[i];

		if (i % 2 == 1) {
			if (c != 0x00) {
				return false;
			}
			continue;
		}

		if (c == 0x00) {
			break;
		}
		else if (c > 0x7F || (c < 0x20 && c != '\r' && c != '\n')) {
			return false;
		}
	}
	return true;
}

bool isCached(std::string str) {
	if (!_cacheFile.is_open()) {
		std::cout << "Failed to open cache file!" << std::endl;
		exit(EXIT_FAILURE);
	}

	_cacheFile.seekg(0, std::ios::beg);

	std::string line;

	while (std::getline(_cacheFile, line)) {
		if (line == str) {
			return true;
		}
	}
	_cacheFile.clear();
	_cacheFile.seekp(0, std::ios::end);
	_cacheFile << str << std::endl;
	return false;
}

void processString(std::vector<char> data, size_t* len, std::string filter, StringSource source) {
	size_t end = 0;

	for (size_t i = 0; i < data.size(); i++) {
		if (data[i] == '\0') {
			end = i;
			break;
		}
	}

	if (!end) return;

	std::string str(&data[0], end);
	str.erase(0, str.find_first_not_of(' '));

	if (str.empty()) return;
	if (!isANSIString(str) && !isWideString(str)) return;
	if (len) *len = str.length();
	if (str.length() - 1 <= 5) return;

	// Replace line breaks with a dot for ease of printing
	for (size_t i = 0; i < str.length(); i++) {
		if (str[i] == '\r' || str[i] == '\n') {
			str[i] = '.';
		}
	}

	if (isCached(str))	return;

	std::smatch match;

	if (!filter.empty() && !std::regex_search(str, match, std::regex(filter)))	return;

	switch (source) {
	case StringSource::LOCAL:
		std::cout << "Found local string: " << str << std::endl;
		break;
	case StringSource::POINTER:
		std::cout << "Found pointer string: " << str << std::endl;
		break;
	case StringSource::HEAP:
		std::cout << "Found heap string: " << str << std::endl;
		break;
	}
}

// Finds values from the stack that are raw values
void findLocalStrings(std::vector<uintptr_t> stack, std::string filter) {
	for (size_t i = 0; i < stack.size(); i++) {		
		size_t copyLen = stack.size() - i;

		if (copyLen > MAX_VALUE_SIZE) copyLen = MAX_VALUE_SIZE;
		
		std::vector<char> value(copyLen);
		memcpy(&value[0], &stack[i], value.capacity());

		size_t strLen = 0;
		processString(value, &strLen, filter, StringSource::LOCAL);

		if (strLen != 0) {
			i += strLen;
		}
	}
}

// Finds values from the stack that are pointers and then reads the values
void findPointerStrings(std::vector<uintptr_t> stack, std::string filter, HANDLE process) {
	for (size_t i = 0; i < stack.size(); i++) {
		std::vector<char> value(MAX_VALUE_SIZE);

		if (ReadProcessMemory(process, reinterpret_cast<void*>(stack[i]), &value[0], value.capacity(), nullptr)) {
			processString(value, nullptr, filter, StringSource::POINTER);
		}
	}
}

// Initializes the stack and calls the string capture functions
void getStackStrings(HANDLE process, HANDLE thread, std::string filter) {
	THREAD_BASIC_INFORMATION tbi;
	memset(&tbi, 0, sizeof(tbi));

	if (!NT_SUCCESS(NtQueryInformationThread(thread, static_cast<THREADINFOCLASS>(ThreadBasicInformation), &tbi, sizeof(tbi), nullptr))) {
		return;
	}

	NT_TIB teb;
	memset(&teb, 0, sizeof(teb));

	if (!ReadProcessMemory(process, tbi.TebBaseAddress, &teb, sizeof(teb), 0)) {
		return;
	}

	size_t size = reinterpret_cast<uintptr_t>(teb.StackBase) - reinterpret_cast<uintptr_t>(teb.StackLimit);

	std::vector<uintptr_t> stack(size);

	if (!ReadProcessMemory(process, teb.StackLimit, &stack[0], stack.capacity(), nullptr)) {
		return;
	}

	findPointerStrings(stack, filter, process);
	findLocalStrings(stack, filter);
}

// Finds strings from the process heap
void getHeapStrings(HANDLE process, std::string filter) {
	MEMORY_BASIC_INFORMATION mbi;

	// Loop all the memory pages and search contents for strings
	for (uint8_t* addr = nullptr; VirtualQueryEx(process, addr, &mbi, sizeof(mbi)); addr += mbi.RegionSize) {
		if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_EXECUTE))) {
			continue;
		}

		std::vector<char> page(mbi.RegionSize);

		if (!ReadProcessMemory(process, mbi.BaseAddress, &page[0], page.capacity(), nullptr)) {
			continue;
		}

		for (size_t i = 0; i < page.size(); i++) {
			if (page[i] == '\0') continue;

			size_t copyLen = page.size() - i;

			if (copyLen > MAX_VALUE_SIZE) copyLen = MAX_VALUE_SIZE;
			
			std::vector<char> heapValue(copyLen);
			memcpy(&heapValue[0], &page[i], heapValue.capacity());

			size_t strLen = 0;
			processString(heapValue, &strLen, filter, StringSource::HEAP);

			if (strLen != 0) i += strLen;	
		}
	}
}

// Gets the system information for all processes in the system
SYSTEM_PROCESS_INFORMATION* getProcessInfo() {
	ULONG length;
	NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &length);

	SYSTEM_PROCESS_INFORMATION* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(malloc(length));

	if (!spi) {
		std::cout << std::format("Failed to allocate {} bytes of memory!", length) << std::endl;
		return nullptr;
	}

	if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, length, nullptr))) {
		free(spi);
		std::cout << "Failed to get the process information! Trying again..." << std::endl;
		return getProcessInfo();
	}
	return spi;
}

bool scanProcess(uint32_t pid, std::string filter, int target) {
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);

	if (!process) {
		std::cout << "Failed to find the process!" << std::endl;
		return false;
	}

	if (target == 0 || target == 1) {
		getHeapStrings(process, filter);
	}

	if (target == 0 || target == 2) {
		SYSTEM_PROCESS_INFORMATION* spi = getProcessInfo();

		if (!spi) {
			return false;
		}

		SYSTEM_PROCESS_INFORMATION* current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
			reinterpret_cast<uint8_t*>(spi) + spi->NextEntryOffset);

		// Loop until the current entry is the target process
		while (reinterpret_cast<uintptr_t>(current->UniqueProcessId) != pid) {
			if (!current->NextEntryOffset) {
				std::cout << "Failed to find the process!" << std::endl;
				return false;
			}
			current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<uint8_t*>(current) + current->NextEntryOffset);
		}

		// The thread information is at the end of SYSTEN_PROCESS_INFORMATION
		SYSTEM_THREAD_INFORMATION* sti = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(reinterpret_cast<uint8_t*>(current) + sizeof(SYSTEM_PROCESS_INFORMATION));

		// Loop all the threads and capture the strings from the stack
		for (uint32_t i = 0; i < current->NumberOfThreads; i++) {
			HANDLE thread = nullptr;

			OBJECT_ATTRIBUTES attr;
			memset(&attr, 0, sizeof(attr));
			attr.Length = sizeof(attr);

			// We use NtOpenThread so we can pass the CLIENT_ID which OpenThread can't do

			if (NT_SUCCESS(NtOpenThread(&thread, THREAD_QUERY_INFORMATION, &attr, &sti->ClientId))) {
				getStackStrings(process, thread, filter);
				CloseHandle(thread);
			}
			sti++;
		}
		free(spi);
	}

	CloseHandle(process);

	return true;
}

uint32_t getProcessByName(std::string name) {
	PROCESSENTRY32 entry;
	memset(&entry, 0, sizeof(PROCESSENTRY32));
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	uint32_t pid = 0;

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (entry.szExeFile == name) {
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

	uint32_t pid = 0;
	input.get("pid", &pid);

	std::string name;

	if (input.get("name", &name)) {
		pid = getProcessByName(name);

		if (!pid) {
			std::cout << "Could not find the process!" << std::endl;
			return -1;
		}
	}

	if (!pid) {
		input.usage();
		return -1;
	}

	int target = 0;
	input.get("target", &target);

	DWORD delay = 1000;
	input.get("delay", &delay);

	while (scanProcess(pid, filter, target)) {
		Sleep(delay);
	}
	_cacheFile.close();
	return 0;
}
