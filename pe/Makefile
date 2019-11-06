MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: live-iat iat-hook

live-iat:
	$(MINGW_CC) live-iat.c -o $(OUTDIR)live-iat$(SUFFIX).exe -nostdlib -lmsvcrt -lkernel32 -Wl,--entry=start

iat-hook:
	$(MINGW_CC) iat-hook.c -o $(OUTDIR)iat-hook$(SUFFIX).exe
