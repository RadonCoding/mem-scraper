#pragma once
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <format>

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI *f_NtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID *ClientId);

f_NtOpenThread NtOpenThread = (f_NtOpenThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenThread");

constexpr DWORD ThreadBasicInformation = 0;
constexpr DWORD MAX_STACK_SIZE = (1024 * 1024) / sizeof(DWORD);
constexpr DWORD MAX_VALUE_SIZE = 1024;
constexpr const char *CACHE_PATH = "cache.txt";

enum StringSource
{
	LOCAL,
	POINTER,
	HEAP
};

class Argument
{
public:
	std::string id;
	std::string shortToken;
	std::string longToken;
	std::string description;

	Argument(std::string id, std::string shortToken, std::string longToken, std::string description)
	{
		this->id = id;
		this->shortToken = shortToken;
		this->longToken = longToken;
		this->description = description;
	}
};

std::vector<Argument> arguments = {
	Argument("help", "-H", "--help", "Shows the usage of arguments"),
	Argument("pid", "-P", "--pid", "The target process identifier"),
	Argument("name", "-N", "--name", "The target process name"),
	Argument("filter", "-F", "--filter", "The regex strings have to match (default = none)"),
	Argument("target", "-T", "--target", "The place to search strings from (1 = heap, 2 = stack, default = both)"),
	Argument("delay", "-D", "--delay", "Delay between scans in milliseconds (default = 1000)")};

class InputParser
{
public:
	InputParser(int &argc, char **argv)
	{
		std::string path(argv[0]);
		this->filename = path.substr(path.find_last_of("/\\") + 1);

		for (int i = 1; i < argc; i++)
		{
			this->tokens.push_back(std::string(argv[i]));
		}
	}

	void parse()
	{
		for (Argument arg : arguments)
		{
			std::vector<std::string>::const_iterator itShort = std::find(this->tokens.begin(), this->tokens.end(), arg.shortToken),
													 itLong = std::find(this->tokens.begin(), this->tokens.end(), arg.longToken);

			if (itShort != this->tokens.end() && ++itShort != this->tokens.end())
			{
				this->parsed.insert(std::make_pair(arg.id, *itShort));
			}
			else if (itLong != this->tokens.end() && ++itLong != this->tokens.end())
			{
				this->parsed.insert(std::make_pair(arg.id, *itLong));
			}
		}
	}

	template <typename T>
	bool get(std::string name, T *value)
	{
		if (!this->contains(name))
		{
			return false;
		}

		if (value)
		{
			std::stringstream ss{this->parsed[name]};
			ss >> *value;
		}
		return true;
	}

	bool contains(std::string name)
	{
		return this->parsed.contains(name);
	}

	void usage()
	{
		std::cout << std::format("Usage: {} [option(s)]", this->filename) << std::endl;
		std::cout << "Options: " << std::endl;

		for (Argument arg : arguments)
		{
			std::cout << std::format("{} {} {}", arg.shortToken, arg.longToken, arg.description) << std::endl;
		}
	}

private:
	std::string filename;
	std::vector<std::string> tokens;
	std::map<std::string, std::string> parsed;
};
