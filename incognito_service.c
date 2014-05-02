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

#define BUFFER_SIZE		500

SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus; 
 
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 
BOOL InitializePipe(LPCTSTR lpszPipe);

HANDLE hPipeR, hPipeW;

void main() 
{ 
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "incognito_service";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;

    // Start the control dispatcher thread for our service
    StartServiceCtrlDispatcher(ServiceTable);  
}

void ServiceMain(int argc, char** argv) 
{ 
    ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler(
		"incognito_service", 
		(LPHANDLER_FUNCTION)ControlHandler); 

    if (hStatus == (SERVICE_STATUS_HANDLE)0) 
    { 
        // Registering Control Handler failed
        return; 
    }  

    // We report the running status to SCM. 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
    SetServiceStatus (hStatus, &ServiceStatus);

	InitializePipe(argv[1]);
	Sleep(100);

	hOUTPUT = hPipeW;
	hINPUT = hPipeR;

	override_connect_remotely = TRUE;
	handle_options(argc-1, ++argv);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED; 
    SetServiceStatus (hStatus, &ServiceStatus);

	Sleep(100);
    return; 
}

// Control handler function
void ControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            ServiceStatus.dwWin32ExitCode = 0; 
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
            SetServiceStatus (hStatus, &ServiceStatus);
            return; 
        
        default:
            break;
    } 
 
    // Report current status
    SetServiceStatus (hStatus,  &ServiceStatus);
 
    return; 
} 

BOOL InitializePipe(LPCTSTR lpszPipe)
{
	char szPipeName[MAX_PATH];

	memset(szPipeName, 0, MAX_PATH);
	if (_snprintf(szPipeName, MAX_PATH, "\\\\.\\pipe\\%s", lpszPipe) == -1)
		szPipeName[sizeof(szPipeName)-1] = '\0';
	
    hPipeW = CreateNamedPipeA(szPipeName, 
                            PIPE_ACCESS_DUPLEX, // read/write access 
                            PIPE_TYPE_MESSAGE | // message type pipe 
                            PIPE_READMODE_MESSAGE | // message-read mode 
                            PIPE_WAIT, // blocking mode 
                            PIPE_UNLIMITED_INSTANCES, // max. instances 
                            BUFFER_SIZE, // output buffer size 
                            BUFFER_SIZE, // input buffer size 
                            10000, // client time-out 
                            NULL); // no security attribute 

	ConnectNamedPipe(hPipeW, NULL);

    hPipeR = CreateNamedPipeA(szPipeName, 
                            PIPE_ACCESS_DUPLEX, // read/write access 
                            PIPE_TYPE_MESSAGE | // message type pipe 
                            PIPE_READMODE_MESSAGE | // message-read mode 
                            PIPE_WAIT, // blocking mode 
                            PIPE_UNLIMITED_INSTANCES, // max. instances 
                            BUFFER_SIZE, // output buffer size 
                            BUFFER_SIZE, // input buffer size 
                            10000, // client time-out 
                            NULL); // no security attribute 

	ConnectNamedPipe(hPipeR, NULL);

	if (hPipeR == INVALID_HANDLE_VALUE || hPipeW == INVALID_HANDLE_VALUE) 
	{
        return FALSE;
	}
	
	return TRUE;
}
