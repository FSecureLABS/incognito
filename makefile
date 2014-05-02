# Shared libraries to link against
LIBS = kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib psapi.lib mpr.lib netapi32.lib Advapi32.lib

# Source files shared between incognito.exe and incognito_service.exe
SHARED_SOURCES = child_process.c handle_arguments.c hash_stealer.c list_tokens.c process_execution.c remote_connection.c token_info.c user_management.c XGetopt.c

CFLAGS = /GS /nologo /W3 /WX -c
LFLAGS = /SAFESEH /nologo

OBJECTS = $(SHARED_SOURCES:.c=.obj)


all: incognito.exe incognito_service.exe find_token.exe

incognito.exe: $(OBJECTS) incognito.obj
	link $(LFLAGS) /OUT:$@ $(OBJECTS) incognito.obj $(LIBS)

incognito_service.exe: $(OBJECTS) incognito_service.obj
	link $(LFLAGS) /OUT:$@ $(OBJECTS) incognito_service.obj $(LIBS)

find_token.exe: find_token.obj
	link $(LFLAGS) /OUT:$@ find_token.obj $(LIBS)

.obj: $(SHARED_SOURCES) 
	cl $(CFLAGS) $@ 

incognito.obj: incognito.c
	cl $(CFLAGS) incognito.c

incognito_service.obj: incognito_service.c
	cl $(CFLAGS) incognito_service.c

find_user.token: find_user.c
	cl $(CFLAGS) find_token.c

clean:
	del *.obj *.exe