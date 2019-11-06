MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: memorylab sampledll windowsversion

memorylab:
	$(MINGW_CC) memorylab.c -o $(OUTDIR)memorylab$(SUFFIX).exe

sampledll:
	$(MINGW_CC) sampledll.c -o $(OUTDIR)sampledll$(SUFFIX).dll -shared

windowsversion:
	$(MINGW_CC) windowsversion.c -o $(OUTDIR)windowsversion$(SUFFIX).exe
