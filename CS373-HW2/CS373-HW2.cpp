// Author: Jason DiMedio
// Date: August 4, 2019
// CS373
// Homework 2
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
#include <sstream>
#include <cstdlib>

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
	if (hProcess != NULL)
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
	LPVOID prev, prev_end_range;
	LPVOID end_range = NULL;
	LPVOID max = si.lpMaximumApplicationAddress;

	DWORD current_state, previous_protect;
	DWORD current_protect = NULL;
	bool mid = false;

	while ((unsigned long long)current < (unsigned long long)max)
	{
		VirtualQueryEx(hProcess, current, &mbi, sizeof(mbi));

		/*
		std::cout << "BaseAddress: " << mbi.BaseAddress << std::endl;
		std::cout << "AllocationProtect: " << getProtection(mbi.AllocationProtect) << std::endl;
		std::cout << "RegionSize: " << mbi.RegionSize << std::endl;
		std::cout << "State: " << mbi.State << std::endl;
		std::cout << "Executable: " << isExecutable(mbi.AllocationProtect) << std::endl;
		*/

		prev = current;
		prev_end_range = end_range;
		current = static_cast<char*>(current) + (unsigned long long)mbi.RegionSize;
		end_range = static_cast<char*>(current) - 1;

		current_state = mbi.State;
		previous_protect = current_protect;
		current_protect = mbi.AllocationProtect;

		/*
		std::cout << "prev: " << prev << std::endl;
		std::cout << "current: " << current << std::endl;
		std::cout << "end_range: " << end_range << std::endl;
		std::cout << "max: " << max << std::endl;
		std::cout << "eval: " << ((unsigned long long)current < (unsigned long long)max) << std::endl;
		*/

		if (isExecutable(current_protect) && (current_state == MEM_COMMIT))
		{
			if (!mid)
			{
				std::cout << "\t" << prev << " - ";
				mid = true;
			}
			else
			{
				if (previous_protect != current_protect)
				{
					std::cout << end_range << "\t" << getProtection(current_protect) << std::endl;
					mid = false;
				}
			}
		}
		else
		{
			if (mid)
			{
				std::cout << prev_end_range << "\t" << getProtection(previous_protect) << std::endl;
				mid = false;
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

void print_usage(std::string n)
{
	std::cout << "USAGE: " << n << " [p|a|r|t|m|e] [Process ID] [Address] [Bytes]" << std::endl;
	std::cout << std::endl;
	std::cout << "p = show one process (must include [Process ID])" << std::endl;
	std::cout << "a = enumerate all processes" << std::endl;
	std::cout << std::endl;
	std::cout << "\tUse with p or a:" << std::endl;
	std::cout << "\tt = show threads" << std::endl;
	std::cout << "\tm = show modules" << std::endl;
	std::cout << "\te = show executable memory pages" << std::endl;
	std::cout << std::endl;
	std::cout << "r = read [Bytes] of virtual memory for [Process ID] starting at [Address]" << std::endl;
	std::cout << std::endl;
	std::cout << "Default (no input): Enumerate all processes" << std::endl;

	exit(0);
}

int main(int argc, char **argv)
{
	std::string name = argv[0];

	bool p = false;
	bool a = false;
	bool r = false;
	bool t = false;
	bool m = false;
	bool e = false;

	if (argc >= 2)
	{
		for (int i = 0; i < strlen(argv[1]); i++)
		{
			if (argv[1][i] == 'p')
				p = true;
			else if (argv[1][i] == 'a')
				a = true;
			else if (argv[1][i] == 'r')
				r = true;
			else if (argv[1][i] == 't')
				t = true;
			else if (argv[1][i] == 'm')
				m = true;
			else if (argv[1][i] == 'e')
				e = true;
		}

		if (!p && !a && !r)
			a = true;
	}
	else
		a = true;

	if (a)
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
				if (t || m || e)
					std::cout << "-------------------------------------------------------------------" << std::endl;
				std::cout << "PROCESS: ";
				PrintProcessNameAndID(aProcesses[i]);

				if (t)
				{
					std::cout << "THREADS: " << std::endl;
					ListProcessThreads(aProcesses[i]);
				}

				if (m)
				{
					std::cout << "MODULES: " << std::endl;
					PrintModules(aProcesses[i]);
				}

				if (e)
				{
					std::cout << "EXECUTABLE PAGES: " << std::endl;
					PrintExecPages(aProcesses[i]);
				}

			}

		}
	}

	else if (p)
	{
		if (argc >= 3)
		{
			DWORD process_input = atoi(argv[2]);

			HANDLE hProcess;

			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, process_input);

			if (NULL != hProcess)
			{
				std::cout << "PROCESS: ";
				PrintProcessNameAndID(process_input);

				if (t)
				{
					std::cout << "THREADS: " << std::endl;
					ListProcessThreads(process_input);
				}

				if (m)
				{
					std::cout << "MODULES: " << std::endl;
					PrintModules(process_input);
				}

				if (e)
				{
					std::cout << "EXECUTABLE PAGES: " << std::endl;
					PrintExecPages(process_input);
				}
			}
			else
				std::cout << "No process with that PID!" << std::endl;


		}
		else
			print_usage(name);

	}
		
	if (r)
	{
		if (argc >= 5)
		{
			DWORD process_input = atoi(argv[2]);
			LPCVOID address;
			std::size_t bytes = atoi(argv[4]);
			std::size_t bytes_read;
			unsigned char* buffer = new unsigned char[bytes];

			std::string adr_str = argv[3];
			address = (LPCVOID)std::stoull(adr_str, nullptr, 16);

			//std::cout << "process_input: " << process_input << std::endl;
			//std::cout << "address: " << address << std::endl;
			//std::cout << "bytes: " << bytes << std::endl;
			//std::cout << "buffer: " << buffer << std::endl;


			HANDLE hProcess;

			// NOTE: The following code was adapted from: https://nullprogram.com/blog/2016/09/03/
			DWORD access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

			// Get a handle to the process.
			hProcess = OpenProcess(access, FALSE, process_input);
			if (NULL != hProcess)
			{
				PrintProcessNameAndID(process_input);

				bool read_mem = ReadProcessMemory(hProcess, address, buffer, bytes, &bytes_read);
				//std::cout << "after read function" << std::endl;

				if (read_mem && (bytes_read <= bytes))
				{
					// NOTE: The following code was adapted from: https://stackoverflow.com/questions/10599068/how-do-i-print-bytes-as-hexadecimal

					//const int size = sizeof(buffer) / sizeof(char);

					std::cout << "MEMORY READ: (" << bytes_read << " bytes)" << std::endl;

					int first = 0;
					int last = 0;

					for (int i = 0; i < bytes_read; i++)
					{
						std::cout << std::hex << std::setfill('0') << std::setw(2) <<  (unsigned int)(const_cast<unsigned char*>(buffer))[i];

						if (((i + 1) % 16) == 0)
						{
							last = i;
							std::cout << "\t\t";

							for (int j = first; j < last; j++)
							{
								if ((const_cast<unsigned char*>(buffer))[j] == '\n')
									std::cout << "\\n";
								else if ((const_cast<unsigned char*>(buffer))[j] == '\r')
									std::cout << "\\r";
								else
									std::cout << (const_cast<unsigned char*>(buffer))[j];
							}
								

							std::cout << std::endl;
							first = i+1;
						}
						else
							std::cout << "  ";
					}

				}
				else
					std::cout << "Nothing read!" << std::endl;
			}
			else
				std::cout << "No process with that PID!" << std::endl;
			
			delete[] buffer;
		}
		else
			print_usage(name);

	}
	   
	return 0;
}