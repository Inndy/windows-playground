void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx);
void hexdump(const void *ptr, size_t size, intptr_t addr);

#ifndef HEXDUMP_LIB
#define HEXDUMP_LIB
#include <stdint.h>

void hexdump_ex(const void *ptr, size_t size, intptr_t addr, void (*cb)(void *, const char *), void *ctx)
{
    const uint8_t *buffer = (const uint8_t *)ptr;

	while(size > 0) {
        uint32_t written;
        char line[128];
		written = snprintf(line, sizeof(line), "%.8llx: ", (uint64_t)addr);

		uint32_t bound = (size >= 16) ? 16 : size;
		int i;
		for(i = 0; i < bound; i++) {
			written += snprintf(line + written, sizeof(line) - written, "%.2x ", buffer[i]);
		}
		for(; i < 16; i++) {
			written += snprintf(line + written, sizeof(line) - written, "   ");
		}
		for(i = 0; i < bound; i++) {
			written += snprintf(line + written, sizeof(line) - written, "%c", (0x20 <= buffer[i] && buffer[i] <= 0x7e) ? buffer[i] : '.');
		}
        
        cb(ctx, line);

		if(size <= 16) {
			return;
		}

		buffer += 16;
		size -= 16;
		addr += 16;
	}
}

void hexdump_cb_default(void *ctx, const char *data)
{
    puts(data);
}

void hexdump(const void *ptr, size_t size, intptr_t addr)
{
    hexdump_ex(ptr, size, addr, hexdump_cb_default, NULL);
}

#define BDUMP(OBJ) hexdump((LPCBYTE)(&OBJ), sizeof(OBJ), (DWORD_PTR)(&OBJ))
#endif
