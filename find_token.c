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
#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>

void enumerate_logged_on_users(char *server, char *username, char *password);

int main(int argc, char *argv[])
{
	FILE *fp;
	char *username, *password, file_line[100], temp_server_name[100];
	BOOL bFileMode = FALSE;

	if (argc < 2)
	{
	  fprintf(stderr, "usage: \n\n%s <server_name_or_ip> | -f <server_list_file> [username] [password]\n", argv[0]);
	  exit(1);
	}
	if (!_stricmp(argv[1], "-f") && argc > 2)
		bFileMode = TRUE;

	if (argc == 5)
	{
		username = argv[3];
		password = argv[4];
	}
	else if (argc == 4)
	{
		username = argv[2];
		password = argv[3];
	}
	else
	{
		username = NULL;
		password = NULL;
	}

	printf("[*] Scanning for logged on users...\n\n");
	printf("Server Name\t\tUsername\n");
	printf("------------------------------------------------------\n");
	
	if (bFileMode)
	{
		fp = fopen(argv[2], "r");
		while (fgets(file_line, sizeof(file_line)-1, fp))
		{
			sscanf(file_line, "%s\n", temp_server_name);
			enumerate_logged_on_users(temp_server_name, username, password);
		}
	}
	else
		enumerate_logged_on_users(argv[1], username, password);
	
	return 0;
}

void enumerate_logged_on_users(char *server, char *username, char *password)
{
	LPWKSTA_USER_INFO_1 pBuf = NULL;
	LPWKSTA_USER_INFO_1 pTmpBuf;
	DWORD dwLevel = 1;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	wchar_t pszServerName[100];
	char ascii_server_name[100];
	NETRESOURCE     nr;

	strcpy(ascii_server_name, "\\\\");
	strncat(ascii_server_name, server, 97);
	ascii_server_name[99] = '\0';
	mbstowcs(pszServerName, ascii_server_name, strlen(ascii_server_name)+1);

	if (username && password)
	{
		nr.dwType    		 = RESOURCETYPE_DISK;
		nr.lpLocalName       = NULL;
		nr.lpProvider        = NULL;
		nr.lpRemoteName 	 = ascii_server_name;

		WNetCancelConnection2A(nr.lpRemoteName, 0, TRUE);
		WNetAddConnection2A(&nr, password, username, 0);
	}

	do // begin do
	{
		nStatus = NetWkstaUserEnum((LPWSTR)pszServerName,
								 dwLevel,
								 (LPBYTE*)&pBuf,
								 dwPrefMaxLen,
								 &dwEntriesRead,
								 &dwTotalEntries,
								 &dwResumeHandle);

		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				for (i = 0; (i < dwEntriesRead); i++)
				{
					assert(pTmpBuf != NULL);

					if (pTmpBuf == NULL)
					{
					  fprintf(stderr, "An access violation has occurred\n");
					  break;
				   }
			   
				   if (!wcschr((wchar_t*)(pTmpBuf)->wkui1_username, L'$'))
				   {
						printf("%s", server);
						wprintf(L"\t\t%s\\%s\n", pTmpBuf->wkui1_logon_domain, pTmpBuf->wkui1_username);
				   }
				   pTmpBuf++;
				   dwTotalCount++;
				}
			}
		}
		else
			fprintf(stderr, "%s\t\tError: %d\n", server, nStatus);
	} while (nStatus == ERROR_MORE_DATA);

	if (pBuf != NULL)
	{
		 NetApiBufferFree(pBuf);
		 pBuf = NULL;
	}
}