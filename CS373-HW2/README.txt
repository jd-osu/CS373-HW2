Author: Jason DiMedio
CS373, Homework 2
August 4, 2019

Note: This project was developed using Visual Studio 2019 v. 16.2.0
- Configuration/Workload: "Desktop development with C++"
- Installation configuration provided in file ".vsconfig" for convenience


Compile instructions:
- Using Visual Studio, open CS373-HW2.sln file.
- Select Build->Build Solution (Ctrl+Shift+B).
- CS373-HW2.exe will be output to directory containing .sln file.


Run instructions:
- Run cmd.exe as Administrator
- Navigate to directory containing CS373-HW2.exe
- Run using usage instructions provided below.



USAGE: CS373-HW2.exe [p|a|r|t|m|e] [Process ID] [Address] [Bytes]

p = show one process (must include [Process ID])
a = enumerate all processes

	Use with p or a:
		t = show threads
		m = show modules
		e = show executable memory pages

r = read [Bytes] of virtual memory for [Process ID] starting at [Address]

Default (no input): Enumerate all processes


Examples:

CS373-HW2.exe										- Enumerates all processes

CS373-HW2.exe atme									- Enumerates all processes, including thread, modules and executable memory pages (WARNING: LONG OUTPUT)

CS373-HW2.exe pe [Process ID]						- Shows executable memory pages for process [Process ID]

CS373-HW2.exe r [ProcessID] [Address] [Bytes]		- Reads [Bytes] of memory for [Process ID] starting at [Address]