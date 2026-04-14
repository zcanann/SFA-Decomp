#include "string.h"
#include "stddef.h"

#define K1 0x80808080
#define K2 0xFEFEFEFF

extern char msl_string_table_1[];

char* strtok_null = msl_string_table_1;
char* strtok_ptr  = msl_string_table_1;
const unsigned char strtok_delimiter_table_init[32] = { 0 };

size_t strlen(const char* str)
{
	size_t len       = -1;
	unsigned char* p = (unsigned char*)str - 1;

	do {
		len++;
	} while (*++p);

	return len;
}

char* strcpy(char* dst, const char* src)
{
	register unsigned char *destb, *fromb;
	register unsigned long w, t, align;

	fromb = (unsigned char*)src;
	destb = (unsigned char*)dst;

	if ((align = ((int)fromb & 3)) != ((int)destb & 3)) {
		goto bytecopy;
	}

	if (align) {
		if ((*destb = *fromb) == 0) {
			return dst;
		}

		for (align = 3 - align; align; align--) {
			if ((*(++destb) = *(++fromb)) == 0) {
				return dst;
			}
		}
		++destb;
		++fromb;
	}

	w = *((int*)(fromb));

	t = w + K2;

	t &= K1;
	if (t) {
		goto bytecopy;
	}
	--((int*)(destb));

	do {
		*(++((int*)(destb))) = w;
		w                    = *(++((int*)(fromb)));

		t = w + K2;
		t &= K1;
		if (t) {
			goto adjust;
		}
	} while (1);

adjust:
	++((int*)(destb));

bytecopy:
	if ((*destb = *fromb) == 0) {
		return dst;
	}

	do {
		if ((*(++destb) = *(++fromb)) == 0) {
			return dst;
		}
	} while (1);

	return dst;
}

char* strncpy(char* dst, const char* src, size_t n)
{
	const unsigned char* p = (const unsigned char*)src - 1;
	unsigned char* q       = (unsigned char*)dst - 1;

	n++;
	while (--n) {
		if (!(*++q = *++p)) {
			while (--n) {
				*++q = 0;
			}
			break;
		}
	}

	return dst;
}

char* strcat(char* dst, const char* src, size_t n)
{
	const unsigned char* srcPtr = (const unsigned char*)src - 1;
	unsigned char* dstPtr       = (unsigned char*)dst - 1;

	(void)n;

	while (*++dstPtr) {
	}

	--dstPtr;
	while ((*++dstPtr = *++srcPtr) != 0) {
	}

	return dst;
}

int strcmp(const char* str1, const char* str2)
{
	register unsigned char* left  = (unsigned char*)str1;
	register unsigned char* right = (unsigned char*)str2;
	unsigned long align, l1, r1, x;

	l1 = *left;
	r1 = *right;
	if (l1 - r1) {
		return l1 - r1;
	}

	if ((align = ((int)left & 3)) != ((int)right & 3)) {
		goto bytecopy;
	}

	if (align) {
		if (l1 == 0) {
			return 0;
		}
		for (align = 3 - align; align; align--) {
			l1 = *(++left);
			r1 = *(++right);
			if (l1 - r1) {
				return l1 - r1;
			}
			if (l1 == 0) {
				return 0;
			}
		}
		left++;
		right++;
	}

	l1 = *(int*)left;
	r1 = *(int*)right;
	x  = l1 + K2;
	if (x & K1) {
		goto adjust;
	}

	while (l1 == r1) {
		l1 = *(++((int*)(left)));
		r1 = *(++((int*)(right)));
		x  = l1 + K2;
		if (x & K1) {
			goto adjust;
		}
	}

	if (l1 > r1) {
		return 1;
	}
	return -1;

adjust:
	l1 = *left;
	r1 = *right;
	if (l1 - r1) {
		return l1 - r1;
	}

bytecopy:
	if (l1 == 0) {
		return 0;
	}

	do {
		l1 = *(++left);
		r1 = *(++right);
		if (l1 - r1) {
			return l1 - r1;
		}
		if (l1 == 0) {
			return 0;
		}
	} while (1);
}

int strncmp(const char* str1, const char* str2, size_t n)
{
    const unsigned char* p1 = (unsigned char*)str1 - 1;
    const unsigned char* p2 = (unsigned char*)str2 - 1;
    unsigned long c1, c2;

    n++;

    while (--n)
        if ((c1 = *++p1) != (c2 = *++p2))
            return (c1 - c2);
        else if (!c1)
            break;
    return 0;
}

char* strchr(const char* str, int c)
{
	const unsigned char* p = (unsigned char*)str - 1;
	unsigned long chr      = (c & 0xFF);

	unsigned long ch;
	while (ch = *++p) {
		if (ch == chr) {
			return (char*)p;
		}
	}

	return chr ? NULL : (char*)p;
}

char* strrchr(const char* str, int c)
{
	const unsigned char* p = (unsigned char*)str - 1;
	const unsigned char* q = NULL;
	unsigned long chr      = (c & 0xFF);

	unsigned long ch;
	while (ch = *++p) {
		if (ch == chr) {
			q = p;
		}
	}

	if (q != NULL) {
		return (char*)q;
	}

	return chr ? NULL : (char*)p;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
char* strtok(char* str, const char* delim)
{
	unsigned char delimiter_table[32];
	int ch;
	unsigned char* p;
	char* tokenStart;

	((unsigned int*)delimiter_table)[0] = ((const unsigned int*)strtok_delimiter_table_init)[0];
	((unsigned int*)delimiter_table)[1] = ((const unsigned int*)strtok_delimiter_table_init)[1];
	((unsigned int*)delimiter_table)[2] = ((const unsigned int*)strtok_delimiter_table_init)[2];
	((unsigned int*)delimiter_table)[3] = ((const unsigned int*)strtok_delimiter_table_init)[3];
	((unsigned int*)delimiter_table)[4] = ((const unsigned int*)strtok_delimiter_table_init)[4];
	((unsigned int*)delimiter_table)[5] = ((const unsigned int*)strtok_delimiter_table_init)[5];
	((unsigned int*)delimiter_table)[6] = ((const unsigned int*)strtok_delimiter_table_init)[6];
	((unsigned int*)delimiter_table)[7] = ((const unsigned int*)strtok_delimiter_table_init)[7];

	if (str != NULL) {
		strtok_ptr = str;
	}

	p = (unsigned char*)delim - 1;
	while ((ch = *++p) != '\0') {
		delimiter_table[(ch & 0xFF) >> 3] |= 1 << (ch & 7);
	}

	p = (unsigned char*)strtok_ptr - 1;
	while ((ch = *++p) != '\0') {
		if ((delimiter_table[(ch & 0xFF) >> 3] & (1 << (ch & 7))) == 0) {
			break;
		}
	}

	if (ch == '\0') {
		strtok_ptr = strtok_null;
		return NULL;
	}

	tokenStart = (char*)p;
	while ((ch = *++p) != '\0') {
		if ((delimiter_table[(ch & 0xFF) >> 3] & (1 << (ch & 7))) != 0) {
			break;
		}
	}

	if (ch == '\0') {
		strtok_ptr = strtok_null;
	} else {
		strtok_ptr = (char*)(p + 1);
		*p = '\0';
	}

	return tokenStart;
}

char* strstr(const char* str, const char* pat)
{
	const unsigned char* s1 = (const unsigned char*)str - 1;
	const unsigned char* p1 = (const unsigned char*)pat - 1;
	unsigned long firstc, c1, c2;

	if ((pat == 0) || (!(firstc = *++p1))) {
		return (char*)str;
	}

	while (c1 = *++s1) {
		if (c1 == firstc) {
			const unsigned char* s2 = s1 - 1;
			const unsigned char* p2 = p1 - 1;

			while ((c1 = *++s2) == (c2 = *++p2) && c1)
				;

			if (!c2)
				return (char*)s1;
		}
	}

	return NULL;
}
