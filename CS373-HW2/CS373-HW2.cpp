// CS373-HW2.cpp : This file contains the 'main' function. Program execution begins and ends there.
// NOTE:	The following code for the PrintProcessNameAndID and relevant sections of the main functions was adapted from: https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
//			The following code for the ListProcessThreads and printError functions was adapted from: https://docs.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list
//			The following code for the PrintModules function and relevant sections of the main function were adapted from: https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process


#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlHelp32.h>
#include <iostream>
#include <sysinfoapi.h>
#include <processthreadsapi.h>
#include <string>
#include <iomanip>

// NOTE: The following code was adapted from: https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
void PrintProcessNameAndID(DWORD processID)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// Print the process name and identifier.

	_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

	// Release the handle to the process.

	CloseHandle(hProcess);
}

//NOTE: The following code was adapted from: https://docs.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list
//  Forward declarations:
BOOL ListProcessThreads(DWORD dwOwnerPID);
void printError(TCHAR* msg);

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		printError((_TCHAR*)"Thread32First");  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			std::wcout << "\t" << te32.th32ThreadID << std::endl;
			//_tprintf((_TCHAR*)("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			//_tprintf(TEXT("\n     base priority  = %d"), te32.tpBasePri);
			//_tprintf(TEXT("\n     delta priority = %d"), te32.tpDeltaPri);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	//_tprintf(TEXT("\n"));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}

void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

//NOTE: The following code was adapted from: https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.

	//printf("\nProcess ID: %u\n", processID);

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return 1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.

				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

std::string getProtection(DWORD protect)
{
	std::string ret_val = "";

	if (protect == 0)
		ret_val = "caller does not have access";
	else if (protect == PAGE_EXECUTE)
		ret_val = "PAGE_EXECUTE";
	else if (protect == PAGE_EXECUTE_READ)
		ret_val = "PAGE_EXECUTE_READ";
	else if (protect == PAGE_EXECUTE_READWRITE)
		ret_val = "PAGE_EXECUTE_READWRITE";
	else if (protect == PAGE_EXECUTE_WRITECOPY)
		ret_val = "PAGE_EXECUTE_WRITECOPY";
	else if (protect == PAGE_NOACCESS)
		ret_val = "PAGE_NOACCESS";
	else if (protect == PAGE_READONLY)
		ret_val = "PAGE_READONLY";
	else if (protect == PAGE_READWRITE)
		ret_val = "PAGE_READWRITE";
	else if (protect == PAGE_WRITECOPY)
		ret_val = "PAGE_WRITECOPY";
	else if (protect == PAGE_TARGETS_INVALID)
		ret_val = "PAGE_TARGETS_INVALID";
	else if (protect == PAGE_TARGETS_NO_UPDATE)
		ret_val = "PAGE_TARGETS_NO_UPDATE";

	return ret_val;
}

bool isExecutable(DWORD protect)
{
	bool ret_val = false;

	if ((protect == PAGE_EXECUTE) ||
		(protect == PAGE_EXECUTE_READ) ||
		(protect == PAGE_EXECUTE_READWRITE) ||
		(protect == PAGE_EXECUTE_WRITECOPY))
		ret_val = true;

	return ret_val;
}

int PrintExecPages(DWORD processID)
{
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return 1;

	//NOTE: The following code was adapted from: https://www.tek-tips.com/viewthread.cfm?qid=12619
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	//std::cout << "min address: " << si.lpMinimumApplicationAddress << std::endl;
	//std::cout << "max address: " << si.lpMaximumApplicationAddress << std::endl;

	//HANDLE process = GetCurrentProcess();

	MEMORY_BASIC_INFORMATION mbi;

	LPVOID current = si.lpMinimumApplicationAddress;
	LPVOID prev, end_range;
	LPVOID max = si.lpMaximumApplicationAddress;
	//std::cout << "current: " << current << std::endl;
	//std::cout << "max: " << max << std::endl;

	while ((unsigned int)current < (unsigned int)max)
	{
		//std::cout << "eval: " << ((unsigned int)current < (unsigned int)max) << std::endl;

		VirtualQueryEx(hProcess, current, &mbi, sizeof(mbi));

		/*
		std::cout << "BaseAddress: " << mbi.BaseAddress << std::endl;
		std::cout << "AllocationProtect: " << getProtection(mbi.AllocationProtect) << std::endl;
		std::cout << "RegionSize: " << mbi.RegionSize << std::endl;
		std::cout << "State: " << mbi.State << std::endl;
		std::cout << "Executable: " << isExecutable(mbi.AllocationProtect) << std::endl;
		*/

		prev = current;
		current = static_cast<char*>(current) + (unsigned int)mbi.RegionSize;
		end_range = static_cast<char*>(current) - 1;

		if (isExecutable(mbi.AllocationProtect) && (mbi.State == MEM_COMMIT))
			std::cout << "\t" << prev << " - " << end_range << "\t" << getProtection(mbi.AllocationProtect) << std::endl;

	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}


int main(void)
{
		// Get the list of process identifiers.
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;

		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			return 1;
		}


		// Calculate how many process identifiers were returned.

		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the name and process identifier for each process.

		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{
				std::cout << "-------------------------------------------------------------------" << std::endl;
				std::cout << "PROCESS: ";
				PrintProcessNameAndID(aProcesses[i]);

				std::cout << "THREADS: " << std::endl;
				ListProcessThreads(aProcesses[i]);

				std::cout << "MODULES: " << std::endl;
				PrintModules(aProcesses[i]);

				std::cout << "EXECUTABLE PAGES: " << std::endl;
				PrintExecPages(aProcesses[i]);
			}

		}


	return 0;
}