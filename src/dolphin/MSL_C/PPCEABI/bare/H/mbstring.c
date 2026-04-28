#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "string.h"

extern const unsigned long lbl_803E7938;

int unicode_to_UTF8(char* s, wchar_t wchar);

size_t wcstombs(char* s, const wchar_t* pwcs, size_t n) {
    int chars_written = 0;
    register int result;
    char temp[3];
    wchar_t* source;

    if (!s || !pwcs)
        return (0);

    source = (wchar_t*)pwcs;
    while (chars_written <= n) {
        if (!*source) {
            *(s + chars_written) = '\0';
            break;
        } else {
            result = unicode_to_UTF8(temp, *source++);
            if ((chars_written + result) <= n) {
                strncpy(s + chars_written, temp, result);
                chars_written += result;
            } else
                break;
        }
    }

    return (chars_written);
}

int unicode_to_UTF8(char* s, wchar_t wchar) {
    int number_of_bytes;
    char* target_ptr;
    unsigned long first_byte_mark;

    first_byte_mark = lbl_803E7938;

    if (!s) {
        return 0;
    }

    if (wchar < 0x0080)
        number_of_bytes = 1;
    else if (wchar < 0x0800)
        number_of_bytes = 2;
    else
        number_of_bytes = 3;

    target_ptr = s + number_of_bytes;

    switch (number_of_bytes) {
    case 3:
        *--target_ptr = (wchar & 0x003f) | 0x80;
        wchar >>= 6;
    case 2:
        *--target_ptr = (wchar & 0x003f) | 0x80;
        wchar >>= 6;
    case 1:
        *--target_ptr = wchar | ((char*)&first_byte_mark)[number_of_bytes];
    }

    return (number_of_bytes);
}
