#include <stddef.h>

extern void TRK_fill_mem(void* dest, int value, unsigned long length);

__declspec(section ".init") void* TRK_memset(void* dest, int value, size_t length)
{
    TRK_fill_mem(dest, value, length);
    return dest;
}

__declspec(section ".init") void* TRK_memcpy(void* dest, const void* src, size_t length)
{
    const char* in;
    char* out;

    for (in = (const char*)src - 1, out = (char*)dest - 1, length++; --length;)
        *++out = *++in;

    return dest;
}
