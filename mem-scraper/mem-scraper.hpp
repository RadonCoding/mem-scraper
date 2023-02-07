#pragma once
#include <Windows.h>
#include <winternl.h>
#include <vector>

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

enum StringSource
{
	STACK,
	HEAP
};