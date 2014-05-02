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
#include <initguid.h>
#include <stdio.h>
#include <Lm.h>
#include <signal.h>
#include "handle_arguments.h"

#define PIPE_FORMAT		"%s\\pipe\\%s"
#define PIPE_TIMEOUT	1000
#define BUFSIZE			1500
#define CHARS_IN_GUID	39
#define MESSAGESIZE		1000

BOOL GetPhysicalPathForShare(char* szServer, char* lpszShare, char** lpszPhysicalPath, int nBufferSize);
BOOL GetAvailableWriteableShare(char* szServer, int nPhysicalBufferSize, char** lplpPhysicalPath, int nUNCPathSize, char** lplpUNCPath);
void connect_to_named_pipe(char *lpszServer);
DWORD WINAPI ReadFromNamedPipe(LPVOID p);
DWORD WINAPI WriteToNamedPipe(LPVOID p);
void handle_interrupt(int signal);
void cleanup(char *server_name, char *username, char *password);

__declspec( thread ) static HANDLE hPipeR, hPipeW;
__declspec( thread ) static GUID guidPipe;
__declspec( thread ) static WCHAR wszGUID[CHARS_IN_GUID + 1];
__declspec( thread ) static char szGUID[CHARS_IN_GUID + 1], rExename[MAX_PATH];
__declspec( thread ) static SC_HANDLE hscm = NULL;
__declspec( thread ) static SC_HANDLE hsvc = NULL;
__declspec( thread ) static SERVICE_STATUS sStatus;

void connect_to_machine(char *server_name, char *username, char *password, int argc, char *argv[], BOOL cleanup_mode)
{
	DWORD i, rc;
	char *szWritableShare = NULL, *szWritableSharePhysical = NULL, machineName[MAX_PATH],
			resourceName[MAX_PATH], szFullServicePath[MAX_PATH], localPath[MAX_PATH], **varg;

	NETRESOURCE rec;
	rec.dwType = RESOURCETYPE_DISK;
	rec.lpLocalName = NULL;
	rec.lpProvider = NULL;

	if (cleanup_mode)
	{
		cleanup(server_name, username, password);
		return;
	}

	if (_snprintf(machineName, MAX_PATH, "\\\\%s", server_name) == -1)
		machineName[sizeof(machineName)-1] = '\0';	
	szWritableShare = (char*)calloc(MAX_PATH + 1, sizeof(char));
	szWritableSharePhysical = (char*)calloc(MAX_PATH + 1, sizeof(char));

	// Make copies of arguments to pass to remote service
	varg = (char**)calloc(argc+3, sizeof(char*));
	if (grepable_mode)
	{
		if (suppress_status)
			varg[1] = "-gq";
		else
			varg[1] = "-g";
		varg[2] = "-h";
		varg[3] = server_name;
		for (i=1;i<(unsigned int)argc;i++)
			varg[i+3] = argv[i];
		argc += 3;
	}
	else if (suppress_status)
	{
		varg[1] = "-q";
		for (i=1;i<(unsigned int)argc;i++)
			varg[i+1] = argv[i];
		argc ++;
	}
	else
	{
		for (i=1;i<(unsigned int)argc;i++)
			varg[i] = argv[i];
	}

	// Register signal handlers and get local path
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGABRT, handle_interrupt);
	GetModuleFileNameA(NULL, localPath, MAX_PATH);

	// Need to establish a connection to enumerate shares sometimes
	sprintf(resourceName, "%s\\IPC$", machineName);
	rec.lpRemoteName = resourceName;

	// Connect to remote host if username and password supplied
	if (username && password)
	{
		output_status_string("[*] Attempting to establish new connection to %s\n", resourceName);

		WNetCancelConnection2A(rec.lpRemoteName, 0, TRUE);

		if ((rc = WNetAddConnection2A(&rec, password, username, 0)))
			output_status_string("[-] Logon to %s failed: error %d\n", resourceName, rc);
		else
			output_status_string("[+] Logon to %s succeeded\n", resourceName);
	}
	else
		output_status_string("[-] No username and password supplied\n");

	if (!GetAvailableWriteableShare(machineName, MAX_PATH, &szWritableSharePhysical, MAX_PATH, &szWritableShare))
	{
		output_status_string("[-] Unable to find writable share on %s\n", machineName);
		return;
	}
	if (strlen(szWritableShare) <= 0 || strlen(szWritableSharePhysical) <= 0)
	{
		output_status_string("[-] Unable to find a writable share on %s\n", machineName);
		return;
	}
	if (_snprintf(szFullServicePath, MAX_PATH,"%s\\%s", szWritableSharePhysical, "incognito_service.exe") == -1)
		szFullServicePath[sizeof(szFullServicePath)-1] = '\0';

	// copy exe file to remote machine
	output_status_string("[*] Copying service to %s\n", machineName);
	strncpy(strrchr(localPath, '\\') + 1, "incognito_service.exe", MAX_PATH-1-(strrchr(localPath, '\\') + 1 - localPath));
	localPath[MAX_PATH-1] = '\0';
	strncpy(rExename, szWritableShare, MAX_PATH-1);
	rExename[MAX_PATH-1] = '\0';
	strncat(rExename, "\\incognito_service.exe", MAX_PATH-strlen(rExename));

	if (!CopyFileA(localPath, rExename, FALSE))
	{
		if (GetLastError() == ERROR_FILE_EXISTS)
			output_status_string("[-] File already exists");
		else 
		{
			output_status_string("[-] Couldn't copy %s to destination %s: %d\n", localPath, rExename, GetLastError());
			return;
		}
	}
	else
		output_status_string("[+] Copied service successfully\n");

	// Need to create a guid for the pipe name
	memset(wszGUID, 0, CHARS_IN_GUID + 1);
	memset(szGUID, 0, CHARS_IN_GUID + 1);

	CoCreateGuid(&guidPipe);
	StringFromGUID2(&guidPipe, wszGUID, CHARS_IN_GUID);
	wcstombs(szGUID, wszGUID, CHARS_IN_GUID+1);

    // establish the service on remote machine
	hscm = OpenSCManagerA(machineName, NULL, SC_MANAGER_CREATE_SERVICE); 

    if(!hscm)
    {
        output_status_string("[-] Failed to open service control manager\n");
		return;
    }

	// Create service
	output_status_string("[*] Creating incognito service on remote host\n");
	hsvc = CreateServiceA(hscm, "incognito_service", "Incognito Service", SERVICE_ALL_ACCESS, 
                                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                szFullServicePath, NULL, NULL, NULL, NULL, NULL);

    if(!hsvc)
    {
		output_status_string("[-] Failed to create service. Attempting to open pre-existing service: %d\n", GetLastError());
		hsvc = OpenServiceA(hscm, "incognito_service", SERVICE_ALL_ACCESS);
        if(!hsvc)
        {
			output_status_string("[-] Failed to open service: %d\n", GetLastError());
			return;
        }
		else 
			output_status_string("[+] Existing service found and opened successfully\n");
    }
	else
		output_status_string("[+] Created service successfully\n");

	// run service
    varg[0] = szGUID;

	output_status_string("[*] Starting service\n");
	if(!StartService(hsvc, argc, (const char**)varg))
	{
        output_status_string("[-] Service start failed: %d\n", GetLastError());
		return;
	}
	else
		output_status_string("[+] Service started\n");

	// Connect to named pipe
	connect_to_named_pipe(machineName);        

	// when the executable is finished running, it can be deleted - clean up
    while (1)
    {
        Sleep(100);

		if (rExename[0] != 0)
			if(DeleteFileA(rExename))
			{
				Sleep(100);
				output_status_string("[*] Service shutdown detected. Service executable file deleted\n");
				break;
			}
    }

	CloseHandle(hPipeR);
	CloseHandle(hPipeW);
	
	output_status_string("[*] Deleting service\n");
	DeleteService(hsvc);
	CloseServiceHandle(hsvc); 
    CloseServiceHandle(hscm);
}

static void connect_to_named_pipe(char *lpszServer)
{
	char szOutputBuffer[2 * MAX_PATH], szPipeName[MAX_PATH];
    int nError = 2;
	DWORD dwThreadId[2], dwMode;

	ZeroMemory(szPipeName, MAX_PATH);
	ZeroMemory(szOutputBuffer, 2 * MAX_PATH);

	if (_snprintf(szPipeName, MAX_PATH, PIPE_FORMAT, lpszServer, szGUID) == -1)
		szPipeName[sizeof(szPipeName)-1] = '\0';

	while (nError == 2)
	{
		BOOL bPipe;

		bPipe = WaitNamedPipeA(szPipeName, 30000);
		if (!bPipe)
		{
			// Error 2 means the pipe is not yet available, keep trying
			nError = GetLastError();
			Sleep(100);
		}
		else
			nError = 0;
		break;
	}

	output_status_string("[*] Connecting to incognito service named pipe\n");
	hPipeR = CreateFileA(szPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);	

	while(GetLastError() == ERROR_PIPE_BUSY)
	{ 
		Sleep(100);
		hPipeR = CreateFileA(szPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);	
	}

	if(hPipeR == INVALID_HANDLE_VALUE)
	{ 
		output_status_string("[-] Failed to create a new client-side pipe: error %d\n", GetLastError());
		return;
	}

	hPipeW = CreateFileA(szPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);	

	while(GetLastError() == ERROR_PIPE_BUSY)
	{ 
		Sleep(100);
		hPipeW = CreateFileA(szPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);	
	}

	if(hPipeW == INVALID_HANDLE_VALUE)
	{ 
		output_status_string("[-] Failed to create a new client-side pipe: error %d\n", GetLastError());
		return;
	}

   dwMode = PIPE_READMODE_MESSAGE; 
   SetNamedPipeHandleState( 
      hPipeR,    // pipe handle 
      &dwMode,  // new pipe mode 
      NULL,     // don't set maximum bytes 
      NULL);    // don't set maximum time 
   SetNamedPipeHandleState( 
      hPipeW,    // pipe handle 
      &dwMode,  // new pipe mode 
      NULL,     // don't set maximum bytes 
      NULL);    // don't set maximum time 

	output_status_string("[+] Successfully connected to named pipe %s\n", szGUID);
	output_status_string("[*] Redirecting I/O to remote process\n");
	if (!grepable_mode)
		output_string("\n");

  	CreateThread(
        NULL,              // default security attributes
        0,                 // use default stack size
        ReadFromNamedPipe,        // thread function
        hPipeR,             // argument to thread function
        0,                 // use default creation flags
        &dwThreadId[0]);   // returns the thread identifier

	  CreateThread(
        NULL,              // default security attributes
        0,                 // use default stack size
        WriteToNamedPipe,        // thread function
        hPipeW,             // argument to thread function
        0,                 // use default creation flags
        &dwThreadId[1]);   // returns the thread identifier

}

static DWORD WINAPI ReadFromNamedPipe(LPVOID p)
{
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];

	while (1)
	{
		if (!ReadFile(p, chBuf, BUFSIZE, &dwRead, NULL) && GetLastError() != ERROR_MORE_DATA) 
			break;
		fwrite(chBuf, sizeof(char), dwRead, hOUTPUT);
	}

	return 0;
}

static DWORD WINAPI WriteToNamedPipe(LPVOID p)
{
	DWORD dwRead, dwWritten;
	CHAR chBuf[BUFSIZE];

	while (1)
	{
		if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), chBuf, BUFSIZE, &dwRead, NULL) && GetLastError() != ERROR_MORE_DATA) 
			break;
		WriteFile(p, chBuf, dwRead, &dwWritten, NULL);
	}	

	return 0;
}

static void handle_interrupt(int signal)
{
	output_status_string("\n\n");
	output_status_string("[*] Caught interrupt signal\n");
	
	output_status_string("[*] Advised to run cleanup command against hosts\n");
    if (!ControlService(hsvc, SERVICE_CONTROL_STOP, &sStatus))
		output_status_string("[-] Failed to stop service: %d\n", GetLastError());

	Sleep(200);

	//exit(signal);
}

static BOOL GetAvailableWriteableShare(char* szServer, int nPhysicalBufferSize, char** lplpPhysicalPath, int nUNCPathSize, char** lplpUNCPath)
{
	// Returns the drive letter if successful, otherwise 0
	PSHARE_INFO_2 BufPtr, p;
	NET_API_STATUS res;
	DWORD er = 0, tr = 0, resume = 0, i;
	wchar_t server[MAX_PATH];
	char szTemp[MAX_PATH], szTemp2[MAX_PATH];
	BOOL bFound = FALSE;
	char szServerWithSlashes[MAX_PATH];

	ZeroMemory(server, MAX_PATH);
	ZeroMemory(szServerWithSlashes, MAX_PATH);
	ZeroMemory(*lplpPhysicalPath, nPhysicalBufferSize);
	ZeroMemory(*lplpUNCPath, nUNCPathSize);
	//_snprintf(szServerWithSlashes, MAX_PATH, "\\\\%s", szServer);
	if (_snprintf(szServerWithSlashes, MAX_PATH, "%s", szServer) == -1)
		szServerWithSlashes[sizeof(szServerWithSlashes)-1] = '\0';
	mbstowcs(server, szServerWithSlashes, strlen(szServerWithSlashes));

	do
	{
		res = NetShareEnum((LPWSTR)server, 2, (LPBYTE*)&BufPtr, -1, &er, &tr, &resume);
		if(res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
		{
			p = BufPtr;
			for(i = 1; i <= er; i++)
			{
				ZeroMemory(szTemp, MAX_PATH);
				wcstombs(szTemp, (LPWSTR)(p->shi2_netname), MAX_PATH);

				// Look for shares that are not SYSVOL or NETLOGON, and that have a physical path 
				if (/* added admin$ fudge*/ !_stricmp(szTemp, "ADMIN$") && _stricmp(szTemp, "SYSVOL") != 0 && _stricmp(szTemp, "NETLOGON") != 0 && wcslen((LPWSTR)(p->shi2_path)) > 0)
				{
					// If this is a potentially workable share, try uploading something
					memset(szTemp2, 0, MAX_PATH);
					if (_snprintf(szTemp2, MAX_PATH, "%s\\%s", szServerWithSlashes, szTemp) == -1)
						szTemp2[sizeof(szTemp2)-1] = '\0';
					if (1/*CanUpload(szTemp2)*/)
					{
						// Success!
						// Copy the physical path to the out variable
						wcstombs(szTemp, (LPWSTR)(p->shi2_path), MAX_PATH);
						strncpy(*lplpPhysicalPath, szTemp, nPhysicalBufferSize);

						// Also copy the UNC path to the out variable
						strncpy(*lplpUNCPath, szTemp2, nUNCPathSize);
						bFound = TRUE;
						break;
					}

					// Otherwise continue and try another share
				}
				
				p++;
			}

			NetApiBufferFree(BufPtr);
		}
		else 
			output_status_string("[-] Error accessing ADMIN$ share: %ld\n",res);
	}
	while (res == ERROR_MORE_DATA); // end do

	return bFound;
}

static void cleanup(char *server_name, char *username, char *password)
{
	//stop service
	// delete service
	// delete file
	DWORD rc;
	char *szWritableShare = NULL, *szWritableSharePhysical = NULL, machineName[MAX_PATH],
			resourceName[MAX_PATH], szFullServicePath[MAX_PATH], localPath[MAX_PATH];

	NETRESOURCE rec;
	rec.dwType = RESOURCETYPE_DISK;
	rec.lpLocalName = NULL;
	rec.lpProvider = NULL;

	if (_snprintf(machineName, MAX_PATH, "\\\\%s", server_name) == -1)
		machineName[sizeof(machineName)-1] = '\0';	
	szWritableShare = (char*)calloc(MAX_PATH + 1, sizeof(char));
	szWritableSharePhysical = (char*)calloc(MAX_PATH + 1, sizeof(char));

	// Register signal handlers and get local path
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGABRT, handle_interrupt);
	GetModuleFileNameA(NULL, localPath, MAX_PATH);

	// Need to establish a connection to enumerate shares sometimes
	sprintf(resourceName, "%s\\IPC$", machineName);
	rec.lpRemoteName = resourceName;

	// Connect to remote host if username and password supplied
	if (username && password)
	{
		output_status_string("[*] Attempting to establish new connection to %s\n", resourceName);

		WNetCancelConnection2A(rec.lpRemoteName, 0, TRUE);

		if ((rc = WNetAddConnection2A(&rec, password, username, 0)))
			output_status_string("[-] Logon to %s failed: error %d\n", resourceName, rc);
		else
			output_status_string("[+] Logon to %s succeeded\n", resourceName);
	}
	else
		output_status_string("[-] No username and password supplied\n");

	if (!GetAvailableWriteableShare(machineName, MAX_PATH, &szWritableSharePhysical, MAX_PATH, &szWritableShare))
	{
		output_status_string("[-] Unable to find writable share on %s\n", machineName);
		return;
	}
	if (strlen(szWritableShare) <= 0 || strlen(szWritableSharePhysical) <= 0)
	{
		output_status_string("[-] Unable to find a writable share on %s\n", machineName);
		return;
	}
	
	if (_snprintf(szFullServicePath, MAX_PATH,"%s\\%s", szWritableSharePhysical, "incognito_service.exe") == -1)
		szFullServicePath[sizeof(szFullServicePath)-1] = '\0';

    // stop and delete the service on remote machine
	hscm = OpenSCManagerA(machineName, NULL, SC_MANAGER_CREATE_SERVICE); 
    if(!hscm)
    {
        output_status_string("[-] Failed to open service control manager\n");
    }
	else
	{
		hsvc = OpenServiceA(hscm, "incognito_service", SERVICE_ALL_ACCESS);
        if(!hsvc)
        {
			output_status_string("[-] Failed to open service: %d\n", GetLastError());
        }
		else
		{
			output_status_string("[*] Stopping and deleting incognito service on remote host\n");
			ControlService(hsvc, SERVICE_CONTROL_STOP, &sStatus);
			DeleteService(hsvc);
			CloseServiceHandle(hsvc);
		}
		CloseServiceHandle(hscm);
	}

	// delete exe file from remote machine
	strncpy(strrchr(localPath, '\\') + 1, "incognito_service.exe", MAX_PATH-1-(strrchr(localPath, '\\') + 1 - localPath));
	localPath[MAX_PATH-1] = '\0';
	strncpy(rExename, szWritableShare, MAX_PATH-1);
	rExename[MAX_PATH-1] = '\0';
	strncat(rExename, "\\incognito_service.exe", MAX_PATH-strlen(rExename));
	
	output_status_string("[*] Deleting service EXE %s\n", rExename);

	if (DeleteFileA(rExename))
		output_status_string("[+] Successfully deleted %s\n", rExename);
	else 
		output_status_string("[-] Couldn't delete %s: %d\n", rExename, GetLastError());
   
}