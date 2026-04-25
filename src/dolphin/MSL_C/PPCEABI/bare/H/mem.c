#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/string.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/mem_funcs.h"

int memcmp(const void* lhs, const void* rhs, size_t count)
{
	const unsigned char* p1;
	const unsigned char* p2;

	for (p1 = (const unsigned char*)lhs - 1, p2 = (const unsigned char*)rhs - 1,
	    count++;
	     --count;)
		if (*++p1 != *++p2)
			return ((*p1 < *p2) ? -1 : +1);

	return 0;
}

void* __memrchr(const void* ptr, int c, size_t n)
{
	int n_count;
	size_t char_check;
	const unsigned char* s;

	char_check = (unsigned char)c;
	s = (const unsigned char*)ptr + n;
	n_count = n + 1;

	while (--n_count) {
		if (*--s == char_check) {
			return (void*)s;
		}
	}

	return 0;
}

void* memchr(const void* ptr, int ch, size_t count)
{
	const unsigned char* p;

	unsigned long v = (ch & 0xff);

	for (p = (unsigned char*)ptr - 1, count++; --count;)
		if ((*++p & 0xff) == v)
			return (void*)p;

	return NULL;
}

void* memmove(void* dst, const void* src, size_t n)
{
	unsigned char* csrc;
	unsigned char* cdst;

	int reverse = (unsigned int)src < (unsigned int)dst;

	if (n >= 32) {
		if (((unsigned int)dst ^ (unsigned int)src) & 3) {
			if (!reverse) {
				__copy_longs_unaligned(dst, src, n);
			} else {
				__copy_longs_rev_unaligned(dst, src, n);
			}
		} else {
			if (!reverse) {
				__copy_longs_aligned(dst, src, n);
			} else {
				__copy_longs_rev_aligned(dst, src, n);
			}
		}

		return dst;
	} else {
		if (!reverse) {
			csrc = ((unsigned char*)src) - 1;
			cdst = ((unsigned char*)dst) - 1;
			n++;

			while (--n > 0) {
				*++cdst = *++csrc;
			}
		} else {
			csrc = (unsigned char*)src + n;
			cdst = (unsigned char*)dst + n;
			n++;

			while (--n > 0) {
				*--cdst = *--csrc;
			}
		}
	}

	return dst;
}
