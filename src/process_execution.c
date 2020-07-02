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
#include "list_tokens.h"
#include "child_process.h"
#include "token_info.h"
#include "handle_arguments.h"

void create_process(HANDLE token, char *command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level);


void execute_process_with_primary_token(char** requested_username, DWORD num_of_targets, char *command, BOOL console_mode)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i, j = 0;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE, delegation_available = FALSE, assignprimarypriv_gained = FALSE;
	TOKEN_PRIVS token_privs;
	
	// Enumerate tokens
	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		return;
	}

	// Process all tokens to get determinue unique names and delegation abilities
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		// get assign primary privilege if its available
		if (!assignprimarypriv_gained && has_assignprimarytoken_priv(token_list[i].token)){
			if (TryEnableAssignPrimaryPriv(token_list[i].token) == 0)
			{
				assignprimarypriv_gained = TRUE;
				ImpersonateLoggedOnUser(token_list[i].token);
			}
		}		
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_GROUP);
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_USER);
	}
	
	if (num_tokens > 0)
	{
		BOOL cleanupneeded = FALSE;
		for (j = 0; j < num_of_targets; j++) {
			for (i = 0; i < num_unique_tokens; i++) {				
				if (!_stricmp(uniq_tokens[i].username, requested_username[j]))//&& uniq_tokens[i].impersonation_available)
				{					
					if (uniq_tokens[i].delegation_available)
						delegation_available = TRUE;
					for (size_t p = 0; p < num_tokens; p++)
					{
						if (is_token(token_list[p].token, requested_username[j]))//&& is_impersonation_token(token_list[i].token))
						{
							if (delegation_available && is_delegation_token(token_list[p].token))
							{
								create_process(token_list[p].token, command, console_mode, SecurityDelegation);
							}
							else
							{
								create_process(token_list[p].token, command, console_mode, SecurityImpersonation);
							}
							i = num_unique_tokens;
							cleanupneeded = TRUE;
							break;
						}
					}
				}
			}			
		}
		if (cleanupneeded) {
			goto cleanup;
		}
	}

cleanup:
	RevertToSelf();
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token);
		CloseHandle(token_list[i].token);	
	free(token_list);
	free(uniq_tokens);
}

void create_process(HANDLE token, char *command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level)
{
	STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	char *zeros = (char *)calloc(1, 0x80);
	//char window_station[100];
	DWORD /**length_needed,**/ sessionid = 1, returned_length;
	HANDLE new_token, primary_token, current_process, current_process_token;

	// Create primary token
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, impersonation_level, TokenPrimary, &primary_token))
	{
		OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &new_token);
	
		// Duplicate to make primary token 
		if (!DuplicateTokenEx(new_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &primary_token))
		{
			return;
		}
	}

	// Associate process with parent process session. This makes non-console connections pop up with GUI hopefully
	current_process = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetCurrentProcessId());   
	OpenProcessToken(current_process, MAXIMUM_ALLOWED, &current_process_token);
	GetTokenInformation(current_process_token, TokenSessionId, &sessionid, sizeof(sessionid), &returned_length);
	SetTokenInformation(primary_token, TokenSessionId, &sessionid, sizeof(sessionid));

	// Create window station if necessary for invisible process
	/*GetUserObjectInformationA(
		GetProcessWindowStation(),
		UOI_NAME,
		(PVOID) window_station,
		100,
		&length_needed
	);*/

	ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb= sizeof(STARTUPINFO);

	//if (!_stricmp(window_station, "WinSta0"))
	si.lpDesktop = "WinSta0\\Default";
	//else
	//	si.lpDesktop = window_station;

	if (console_mode)
	{		
		CreateProcessWithPipeComm(primary_token, command);
		return;
	}
	else
	{
		CreateProcessAsUserA(
			primary_token,     // client's access token
			NULL,              // file to execute
			command,           // command line
			NULL,              // pointer to process SECURITY_ATTRIBUTES
			NULL,              // pointer to thread SECURITY_ATTRIBUTES
			FALSE,             // handles are not inheritable
			CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,// creation flags
			NULL,              // pointer to new environment block
			NULL,              // name of current directory
			&si,               // pointer to STARTUPINFO structure
			(LPPROCESS_INFORMATION)zeros                // receives information about new process
		);
	}
	
	CloseHandle(primary_token);
}