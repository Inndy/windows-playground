MINGW_CC ?= x86_64-w64-mingw32-gcc
SUFFIX ?=
OUTDIR ?= ../bin/

all: loadlibrary loadsc injector runasystem
	(cd runwithdll; make)

loadlibrary:
	$(MINGW_CC) loadlibrary.c -o $(OUTDIR)loadlibrary$(SUFFIX).exe

loadsc:
	$(MINGW_CC) loadsc.c -o $(OUTDIR)loadsc$(SUFFIX).exe

injector:
	$(MINGW_CC) -municode injector.c -o $(OUTDIR)injector$(SUFFIX).exe -lpsapi

runasystem:
	$(MINGW_CC) -municode runasystem.c -o $(OUTDIR)runasystem$(SUFFIX).exe -lpsapi
