extern void TRK_fill_mem(void* dest, int value, unsigned long length);

void* TRK_memset(void* dest, int value, unsigned long length)
{
    TRK_fill_mem(dest, value, length);
    return dest;
}

void* TRK_memcpy(void* dest, const void* src, unsigned long length)
{
    unsigned char* out = (unsigned char*)dest;
    const unsigned char* in = (const unsigned char*)src;
    while (length != 0) {
        *out++ = *in++;
        length--;
    }
    return dest;
}

