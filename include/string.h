void *memcpy_embed(void *dest, void *src, size_t sz)
{
	unsigned char *d = (unsigned char *)dest,
				  *s = (unsigned char *)src;

	for(size_t i = 0; i < sz; i++) {
		d[i] = s[i];
	}

	return dest;
}

void *memset_embed(void *dest, int c, size_t sz)
{
	unsigned char *d = (unsigned char *)dest;

	for(size_t i = 0; i < sz; i++) {
		d[i] = c;
	}

	return dest;
}

char* strcpy_embed(char *dest, const char *src)
{
	unsigned char *d = (unsigned char *)dest;
	const unsigned char *s = (const unsigned char *)src;
	size_t i = 0;

	if(dest == NULL) return NULL;

	do {
		d[i] = s[i];
	} while(s[i++]);

	return dest;
}

#define memcpy memcpy_embed
#define memset memset_embed
#define strcpy strcpy_embed
