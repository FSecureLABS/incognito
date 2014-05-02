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
#include "handle_arguments.h"

BOOL get_domain_from_token(HANDLE token, char *domain_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	strcpy(domain_to_return, domainname);

	return TRUE;
}

BOOL get_domain_username_from_token(HANDLE token, char *full_name_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

 	// Make full name in DOMAIN\USERNAME format
	sprintf(full_name_to_return, "%s\\%s", domainname, username);

	return TRUE;
}

BOOL get_domain_groups_from_token(HANDLE token, char **group_name_array[], DWORD *num_groups)
{
	LPVOID TokenGroupsInfo[BUF_SIZE];
	char groupname[BUF_SIZE], domainname[BUF_SIZE];
	DWORD i, group_length = sizeof(groupname), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenGroups, TokenGroupsInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;

	*group_name_array = (char**)calloc(((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount, sizeof(char*));
	*num_groups = ((TOKEN_GROUPS*)TokenGroupsInfo)->GroupCount;

	for (i=0;i<*num_groups;i++)
	{
		if((((TOKEN_GROUPS*)TokenGroupsInfo)->Groups[i].Attributes & SE_GROUP_ENABLED) != 0)
		{
			group_length = BUF_SIZE;
			domain_length = BUF_SIZE; // fix bug with insufficient buffer size due to reusing last length value
			LookupAccountSidA(NULL, ((TOKEN_GROUPS*)TokenGroupsInfo)->Groups[i].Sid, groupname, &group_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);
			(*group_name_array)[i] = (char*)calloc(BUF_SIZE, sizeof(char));
			// Make full name in DOMAIN\GROUPNAME format
			sprintf((*group_name_array)[i], "%s\\%s", domainname, groupname);
		}
		else
		{
			(*group_name_array)[i] = (char*)calloc(BUF_SIZE, sizeof(char));
			sprintf((*group_name_array)[i], "%s\\%s", domainname, groupname);
		}
	} 	

	return TRUE;
}

BOOL is_delegation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) == SecurityDelegation)
		return TRUE;
	else
		return FALSE;

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_impersonation_token(HANDLE token)
{
	HANDLE temp_token;
	BOOL ret;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	DWORD returned_tokinfo_length;

	if (GetTokenInformation(token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length))
	if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) >= SecurityImpersonation)
		return TRUE;
	else
		return FALSE;

	ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL is_token(HANDLE token, char *requested_name)
{	
	DWORD i, num_groups=0;
	char *full_name, **group_name_array = NULL;
	BOOL ret = FALSE;

	// If token is NULL then return
	if (!token)
		return FALSE;

	full_name = calloc(BUF_SIZE, sizeof(char));
	get_domain_username_from_token(token, full_name);
	if (!_stricmp(requested_name, full_name))
		ret = TRUE;

	get_domain_groups_from_token(token, &group_name_array, &num_groups);
	
	for (i=0;i<num_groups;i++)
	{
		if (!_stricmp(requested_name, group_name_array[i]))
			ret = TRUE;
		free(group_name_array[i]);
	}

	// Cleanup
	free(group_name_array);
	free(full_name);

	return ret;
}

BOOL is_local_system()
{
	HANDLE token;
	char full_name[BUF_SIZE];

	// If there is a thread token use that, otherwise use current process token
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &token))
		OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
	
	get_domain_username_from_token(token, full_name);
	CloseHandle(token);

	if (!_stricmp("NT AUTHORITY\\SYSTEM", full_name))
		return TRUE;
	else
		return FALSE;
}

BOOL has_impersonate_priv(HANDLE hToken)
{
    LUID luid;
	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length, i;
	char privilege_name[BUF_SIZE];

    if(!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid))
        goto exit;

    if (GetTokenInformation(hToken, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
	{
		for (i=0;i<((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount;i++)
		{
			returned_name_length = BUF_SIZE;
			LookupPrivilegeNameA(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
			if (strcmp(privilege_name, "SeImpersonatePrivilege") == 0)
				return TRUE;
		}
	}

 exit:
    if(hToken) 
		CloseHandle(hToken);

    return FALSE;
}

BOOL has_assignprimarytoken_priv(HANDLE hToken)
{
    LUID luid;
	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length, i;
	char privilege_name[BUF_SIZE];

    if(!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid))
        goto exit;

    if (GetTokenInformation(hToken, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
	{
		for (i=0;i<((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount;i++)
		{
			returned_name_length = BUF_SIZE;
			LookupPrivilegeNameA(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
			if (strcmp(privilege_name, "SeAssignPrimaryTokenPrivilege") == 0)
				return TRUE;
		}
	}

 exit:
    if(hToken) 
		CloseHandle(hToken);

    return FALSE;
}

DWORD TryEnableDebugPriv(HANDLE token)
{
    HANDLE hToken = token;
    DWORD dwError = 0;
    TOKEN_PRIVILEGES privileges;

    if(hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
    {
        dwError = GetLastError();
		goto exit;
    }

    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
    {
        dwError = GetLastError();
        goto exit;
    }

    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    privileges.PrivilegeCount = 1;
    
    if(AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
    {
        dwError = GetLastError();
        goto exit;
    }

 exit:
    if(token == NULL && hToken) 
		CloseHandle(hToken);

    return dwError;
}

DWORD TryEnableAssignPrimaryPriv(HANDLE token)
{
    HANDLE hToken = token;
    DWORD dwError = 0;
    TOKEN_PRIVILEGES privileges;

    if(hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
    {
        dwError = GetLastError();
		goto exit;
    }

    if(!LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &privileges.Privileges[0].Luid))
    {
        dwError = GetLastError();
        goto exit;
    }

    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    privileges.PrivilegeCount = 1;
    
    if(AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
    {
        dwError = GetLastError();
        goto exit;
    }

 exit:
    if(token == NULL && hToken) 
		CloseHandle(hToken);

    return dwError;
}