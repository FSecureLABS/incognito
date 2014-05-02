/*
Software License Agreement (BSD License)

Copyright (c) 2006, Luke Jennings (0xlukej@gmail.com)
All rights reserved.

Redistribution and use of this software in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other
  materials provided with the distribution.

* Neither the name of Luke Jennings nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior
  written permission of Luke Jennings.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#define _CRT_SECURE_NO_DEPRECATE 1
#include <windows.h>
#include <stdio.h>
#include "handle_arguments.h"

#define BUFSIZE 4096

static HANDLE hChildStdinRd, hChildStdinWr,
   hChildStdoutRd, hChildStdoutWr, hStdout;

void CreateChildProcess(HANDLE, char*, PROCESS_INFORMATION*);
DWORD WINAPI WriteToPipe(LPVOID);
DWORD WINAPI ReadFromPipe(LPVOID);


void CreateProcessWithPipeComm(HANDLE token, char *command)
{
	PROCESS_INFORMATION piProcInfo;
	SECURITY_ATTRIBUTES saAttr;
	DWORD dwThreadId[2];
    HANDLE hThread[2];

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Get the handle to the current STDOUT.
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0))
	{
		output_status_string("[-] Stdout pipe creation failed\n");
		return;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	SetHandleInformation( hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0))
	{
		output_status_string("[-] Stdin pipe creation failed\n");
		return;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	SetHandleInformation( hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

	// Now create the child process.
	CreateChildProcess(token, command, &piProcInfo);

  	hThread[0] = CreateThread(
            NULL,              // default security attributes
            0,                 // use default stack size
            ReadFromPipe,        // thread function
            NULL,             // argument to thread function
            0,                 // use default creation flags
            &dwThreadId[0]);   // returns the thread identifier

	hThread[1] = CreateThread(
            NULL,              // default security attributes
            0,                 // use default stack size
            WriteToPipe,        // thread function
            NULL,             // argument to thread function
            0,                 // use default creation flags
            &dwThreadId[1]);   // returns the thread identifier

	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
}

static void CreateChildProcess(HANDLE token, char *command, PROCESS_INFORMATION *piProcInfo)
{
	STARTUPINFO siStartInfo;
	BOOL bFuncRetn = FALSE;
	HWINSTA new_winstation, old_winstation;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory( piProcInfo, sizeof(PROCESS_INFORMATION) );

	// Set up members of the STARTUPINFO structure.
	ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hChildStdoutWr;
	siStartInfo.hStdOutput = hChildStdoutWr;
	siStartInfo.hStdInput = hChildStdinRd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	siStartInfo.lpDesktop = "incognito\\default";

	// Create new window station and save handle to existing one
	old_winstation = GetProcessWindowStation();
	new_winstation = CreateWindowStationA(
						  "incognito",
						  (DWORD)NULL,
						  MAXIMUM_ALLOWED,
						  NULL
						  );
	
	// Set process to new window station and create new desktop object within it
	SetProcessWindowStation(new_winstation);
	CreateDesktopA(
	  "default",
	  NULL,
	  NULL,
	  (DWORD)NULL,
	  GENERIC_ALL,
	  NULL
	);
	SetProcessWindowStation(old_winstation);

	// Create the child process.
	bFuncRetn = CreateProcessAsUserA(
	  token,
	  NULL,
	  command,     // command line
	  NULL,          // process security attributes
	  NULL,          // primary thread security attributes
	  TRUE,          // handles are inherited
	  0,             // creation flags
	  NULL,          // use parent's environment
	  NULL,          // use parent's current directory
	  &siStartInfo,  // STARTUPINFO pointer
	  piProcInfo);  // receives PROCESS_INFORMATION

	if (bFuncRetn == 0)
		output_status_string("[-] Failed to create new process: %d\n", GetLastError());
}

static DWORD WINAPI WriteToPipe(LPVOID p)
{
	DWORD dwRead, dwWritten;
	CHAR chBuf[BUFSIZE];

	for (;;)
	{
		if (!read_counted_input(chBuf, BUFSIZE, &dwRead)) 
			break;
		chBuf[dwRead-1] = '\n';
		if (! WriteFile(hChildStdinWr, chBuf, dwRead,
			&dwWritten, NULL)) 
			break;
	}
   	return 0;
}

static DWORD WINAPI ReadFromPipe(LPVOID p)
{
   DWORD dwRead;
   CHAR chBuf[BUFSIZE];

   for (;;)
   {
		if( !ReadFile( hChildStdoutRd, chBuf, BUFSIZE, &dwRead,
			NULL) || dwRead == 0) break;
		if (!output_counted_string(chBuf, dwRead))
			break;
   }

   return 0;
}
