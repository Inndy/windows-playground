MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: mypslist mykill querypeb readprocessmemory writeprocessmemory

mypslist:
	$(MINGW_CC) mypslist.c -o $(OUTDIR)mypslist$(SUFFIX).exe -lpsapi

mykill:
	$(MINGW_CC) mykill.c -o $(OUTDIR)mykill$(SUFFIX).exe

querypeb:
	$(MINGW_CC) querypeb.c -o $(OUTDIR)querypeb$(SUFFIX).exe -lntdll

readprocessmemory:
	$(MINGW_CC) readprocessmemory.c -o $(OUTDIR)readprocessmemory$(SUFFIX).exe

writeprocessmemory:
	$(MINGW_CC) writeprocessmemory.c -o $(OUTDIR)writeprocessmemory$(SUFFIX).exe

run-notepad-suspended:
	$(MINGW_CC) run-notepad-suspended.c -o $(OUTDIR)run-notepad-suspended$(SUFFIX).exe
