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
#include "token_info.h"
#include "process_execution.h"
#include "list_tokens.h"
#include "handle_arguments.h"
#include "XGetopt.h"

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
		WriteFile(hOUTPUT, temp, (DWORD)strlen(temp), &dwWritten, NULL);

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
			WriteFile(hOUTPUT, host, (DWORD)strlen(host), &dwWritten, NULL);
			WriteFile(hOUTPUT, " / [Status] / ", (DWORD)strlen(" / [Status] / "), &dwWritten, NULL);
		}
		WriteFile(hOUTPUT, temp, (DWORD)strlen(temp), &dwWritten, NULL);
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
		WriteFile(hOUTPUT, host, (DWORD)strlen(host), &dwWritten, NULL);
		WriteFile(hOUTPUT, " / ", (DWORD)strlen(" / "), &dwWritten, NULL);
		WriteFile(hOUTPUT, temp, (DWORD)strlen(temp), &dwWritten, NULL);
	}

	va_end(ap);
}

BOOL output_counted_string(char *string, DWORD dwRead)
{
	DWORD dwWritten;

	if (hOUTPUT == stdout){
		DWORD dwWritten = (DWORD)fwrite(string, sizeof(char), dwRead, hOUTPUT);
		fflush(hOUTPUT);
		return dwWritten;
	} else
		return WriteFile(hOUTPUT, string, dwRead, &dwWritten, NULL);
}

BOOL read_counted_input(char *string, int string_size, DWORD *dwRead)
{
	char *ret_value;

	if (hINPUT == stdin)
	{
		ret_value = gets(string);
		*dwRead = (DWORD)strlen(string)+1;
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
	output_string("Usage:\n\n");
	output_string("%s [global options] COMMAND [options] arguments\n", programName);
	output_string("\n\n");


	output_string("GLOBAL OPTIONS:\n\n");
	output_string("\t-g \t\tGrepable output mode\n");
	output_string("\t-q \t\tQuiet mode (suppress status messages)\n");
	output_string("\n\n");


	output_string("COMMANDS:\n\n");
	output_string("\tlt [options]\t\n\n");
	output_string("\t\t-u\tList by unique username\n");
	output_string("\t\t-g\tList by unique groupname\n");
	output_string("\n");

	output_string("\texe [options] <token> <command>\t\n\n");
	output_string("\t\t-c\tEnable communication by console\n");
	output_string("\n");
		
	output_string("\n");
}

static BOOL user_supplied = FALSE, pass_supplied = FALSE;
static char username[BUF_SIZE], password[BUF_SIZE];
static int argc_global;
static char **argv_global;
static BOOL cleanup_mode = FALSE;

void handle_options(int argc, char *argv[])
{	
	int c, MAX_THREADS = 10;
	char *command, host_to_add_user[BUF_SIZE] = "127.0.0.1", *thread_specific_host = NULL;
	BOOL console_mode = FALSE, file_mode = FALSE;

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
			case '?': output_string("[-] Unknown global option %s\n", argv[optind-1]); return;
			case ':': output_string("[-] %s option argument was not supplied\n", argv[optind-1]); return;
		}	
	}
		
	// Set incognito command (list_tokens, execute, snarf_hashes etc)
	if (optind < argc)
		command = argv[optind];

	// Increment optind to point to command specific options and arguments
	optind += 1;

	if (!is_local_system())
		output_status_string("[-] WARNING: Not running as SYSTEM. Not all tokens will be available.\n");

	// Handle each different command
	if (!_stricmp("lt", command))
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
	else if (!_stricmp("exe", command))
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

		execute_process_with_primary_token(argv[optind], 1, argv[optind+1], console_mode);
		return;
	}
	else
		output_string("[-] Unknown command %s\n", command);
	
	return;
}
