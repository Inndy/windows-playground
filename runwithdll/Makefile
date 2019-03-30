all: runwithdll samplehook

.PHONY: all

shellcode:
	i686-w64-mingw32-gcc shellcode.c -O3 -falign-functions=1 -fno-asynchronous-unwind-tables -fno-toplevel-reorder -O -o shellcode.o
	i686-w64-mingw32-objcopy -O binary -j shell shellcode.o shellcode.bin
	xxd -g16 shellcode.bin | cut -f 2 -d ' ' | tr -d '\n' | sed -e 's/../\\x&/g' -e 's/^/char shellcode[] = "/' -e 's/$$/";\n/g' > shellcode.h

runwithdll: shellcode
	i686-w64-mingw32-gcc runwithdll.c -o runwithdll.exe

samplehook:
	i686-w64-mingw32-gcc samplehook.c -shared -o samplehook.dll

clean:
	rm *.exe *.o *.bin *.dll shellcode.h
