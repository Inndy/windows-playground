MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: bind-shell

bind-shell:
	$(MINGW_CC) bind-shell.c -o $(OUTDIR)bind-shell$(SUFFIX).exe -lws2_32
