MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: findnotepad listwindow

findnotepad:
	$(MINGW_CC) findnotepad.c -o $(OUTDIR)findnotepad$(SUFFIX).exe

listwindow:
	$(MINGW_CC) listwindow.c -o $(OUTDIR)listwindow$(SUFFIX).exe
