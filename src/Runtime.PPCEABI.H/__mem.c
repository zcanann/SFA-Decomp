#include "stddef.h"

void __fill_mem(void* dest, int val, size_t count)
{
    unsigned char* out = (unsigned char*)dest;
    while (count != 0) {
        *out++ = (unsigned char)val;
        count--;
    }
}

void* memset(void* dest, int val, size_t count)
{
    __fill_mem(dest, val, count);
    return dest;
}

