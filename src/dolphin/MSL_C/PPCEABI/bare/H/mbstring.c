#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "string.h"

int unicode_to_UTF8(char* s, wchar_t wchar);

size_t wcstombs(char* s, const wchar_t* pwcs, size_t n) {
    size_t written = 0;

    if (s == 0 || pwcs == 0) {
        return 0;
    }

    while (written <= n) {
        char encoded[4];
        int count;

        if (*pwcs == 0) {
            s[written] = 0;
            break;
        }

        count = unicode_to_UTF8(encoded, *pwcs++);
        if (written + count > n) {
            break;
        }

        strncpy(s + written, encoded, count);
        written += count;
    }

    return written;
}

int unicode_to_UTF8(char* s, wchar_t wchar) {
    unsigned int c = (unsigned short)wchar;

    if (s == 0) {
        return 0;
    }

    if (c < 0x80) {
        s[0] = (char)c;
        return 1;
    }

    if (c < 0x800) {
        s[0] = (char)(0xC0 | (c >> 6));
        s[1] = (char)(0x80 | (c & 0x3F));
        return 2;
    }

    s[0] = (char)(0xE0 | (c >> 12));
    s[1] = (char)(0x80 | ((c >> 6) & 0x3F));
    s[2] = (char)(0x80 | (c & 0x3F));
    return 3;
}
