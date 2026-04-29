#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_fp.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/float.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/limits.h"

extern const double lbl_803E7930;

int __count_trailing_zerol(unsigned long x) {
    int result = 0;
    int bits_not_checked = sizeof(unsigned long) * CHAR_BIT;
    int n = bits_not_checked / 2;
    int mask_size = n;
    unsigned long mask = (~0UL) >> (bits_not_checked - n);

    while (bits_not_checked) {
        if (!(x & mask)) {
            result += mask_size;
            x >>= mask_size;
            bits_not_checked -= mask_size;
        } else if (mask == 1) {
            break;
        }

        if (n > 1) {
            n /= 2;
        }

        if (mask > 1) {
            mask >>= n;
            mask_size -= n;
        }
    }
    return result;
}

static inline int __count_trailing_zero(double x) {
    unsigned long* l = (unsigned long*)&x;

    if (l[1] != 0) {
        return __count_trailing_zerol(l[1]);
    }

    return (int)(sizeof(unsigned long) * CHAR_BIT + __count_trailing_zerol(l[0] | 0x00100000));
}

static inline void __dorounddecup(decimal* d, int digits) {
    unsigned char* b = d->sig.text;
    unsigned char* i = b + digits - 1;

    while (1) {
        if (*i < 9) {
            *i += 1;
            break;
        }
        if (i == b) {
            *i = 1;
            d->exp++;
            break;
        }
        *i-- = 0;
    }
}

void __ull2dec(decimal* result, unsigned long long val) {
    result->sign = 0;

    if (val == 0) {
        result->exp = 0;
        result->sig.length = 1;
        result->sig.text[0] = 0;
        return;
    }

    if (val < 0) {
        val = -val;
        result->sign = 1;
    }

    result->sig.length = 0;

    for (; val != 0; val /= 10) {
        result->sig.text[result->sig.length++] = (unsigned char)(val % 10);
    }

    {
        unsigned char* i = result->sig.text;
        unsigned char* j = result->sig.text + result->sig.length;

        for (; i < --j; ++i) {
            unsigned char t = *i;
            *i = *j;
            *j = t;
        }
    }

    result->exp = result->sig.length - 1;
}

void __timesdec(decimal* result, const decimal* x, const decimal* y) {
    unsigned long accumulator = 0;
    unsigned char mantissa[SIGDIGLEN * 2];
    int i = x->sig.length + y->sig.length - 1;
    unsigned char* pDigit;
    unsigned char* ip = mantissa + i + 1;
    unsigned char* ep = ip;

    result->sign = 0;

    for (; i > 0; i--) {
        int k = y->sig.length - 1;
        int j = i - k - 1;
        int l;
        int t;
        const unsigned char* jp;
        const unsigned char* kp;

        if (j < 0) {
            j = 0;
            k = i - 1;
        }

        jp = x->sig.text + j;
        kp = y->sig.text + k;
        l = k + 1;
        t = x->sig.length - j;

        if (l > t)
            l = t;

        for (; l > 0; --l, ++jp, --kp) {
            accumulator += *jp * *kp;
        }

        *--ip = (unsigned char)(accumulator % 10);
        accumulator /= 10;
    }

    result->exp = (short)(x->exp + y->exp);

    if (accumulator) {
        *--ip = (unsigned char)(accumulator);
        result->exp++;
    }

    for (i = 0; i < SIGDIGLEN && ip < ep; ++i, ++ip) {
        result->sig.text[i] = *ip;
    }
    result->sig.length = (unsigned char)(i);

    if (ip < ep && *ip >= 5) {
        if (*ip == 5) {
            unsigned char* jp = ip + 1;
            for (; jp < ep; jp++) {
                if (*jp != 0)
                    goto round;
            }
            if ((ip[-1] & 1) == 0)
                return;
        }
    round:
        __dorounddecup(result, result->sig.length);
    }
}

void __str2dec(decimal* d, const char* s, short exp) {
    int i;

    d->exp = exp;
    d->sign = 0;

    for (i = 0; i < SIGDIGLEN && *s;) {
        d->sig.text[i++] = *s++ - '0';
    }
    d->sig.length = i;

    if (*s != 0) {
        if (*s < 5)
            return;

        {
            const char* p = s + 1;

            for (; *p != 0; p++) {
                if (*p != '0')
                    goto round;
            }

            if ((d->sig.text[i - 1] & 1) == 0)
                return;
        }
    round:
        __dorounddecup(d, d->sig.length);
    }
}

const char lbl_802C2A18[] = "179769313486231580793729011405303420\000"
                            "542101086242752217003726400434970855712890625\000"
                            "11102230246251565404236316680908203125\000"
                            "23283064365386962890625\000"
                            "152587890625\000"
                            "390625\000"
                            "78125\000"
                            "15625\000"
                            "3125\000"
                            "625\000"
                            "125\000"
                            "25\000"
                            "5\000"
                            "1\000"
                            "2\000"
                            "4\000"
                            "8\000"
                            "16\000"
                            "32\000"
                            "64\000"
                            "128\000"
                            "256\000\000\000";

void __two_exp(decimal* result, short exp) {
    switch (exp) {
    case -64:
        __str2dec(result, lbl_802C2A18 + 0x25, -20);
        return;
    case -53:
        __str2dec(result, lbl_802C2A18 + 0x53, -16);
        return;
    case -32:
        __str2dec(result, lbl_802C2A18 + 0x7A, -10);
        return;
    case -16:
        __str2dec(result, lbl_802C2A18 + 0x92, -5);
        return;
    case -8:
        __str2dec(result, lbl_802C2A18 + 0x9F, -3);
        return;
    case -7:
        __str2dec(result, lbl_802C2A18 + 0xA6, -3);
        return;
    case -6:
        __str2dec(result, lbl_802C2A18 + 0xAC, -2);
        return;
    case -5:
        __str2dec(result, lbl_802C2A18 + 0xB2, -2);
        return;
    case -4:
        __str2dec(result, lbl_802C2A18 + 0xB7, -2);
        return;
    case -3:
        __str2dec(result, lbl_802C2A18 + 0xBB, -1);
        return;
    case -2:
        __str2dec(result, lbl_802C2A18 + 0xBF, -1);
        return;
    case -1:
        __str2dec(result, lbl_802C2A18 + 0xC2, -1);
        return;
    case 0:
        __str2dec(result, lbl_802C2A18 + 0xC4, 0);
        return;
    case 1:
        __str2dec(result, lbl_802C2A18 + 0xC6, 0);
        return;
    case 2:
        __str2dec(result, lbl_802C2A18 + 0xC8, 0);
        return;
    case 3:
        __str2dec(result, lbl_802C2A18 + 0xCA, 0);
        return;
    case 4:
        __str2dec(result, lbl_802C2A18 + 0xCC, 1);
        return;
    case 5:
        __str2dec(result, lbl_802C2A18 + 0xCF, 1);
        return;
    case 6:
        __str2dec(result, lbl_802C2A18 + 0xD2, 1);
        return;
    case 7:
        __str2dec(result, lbl_802C2A18 + 0xD5, 2);
        return;
    case 8:
        __str2dec(result, lbl_802C2A18 + 0xD9, 2);
        return;
    }

    {
        decimal x2, temp;

        __two_exp(&x2, exp / 2);
        __timesdec(result, &x2, &x2);

        if (exp & 1) {
            temp = *result;
            if (exp > 0) {
                decimal temp2;
                __str2dec(&temp2, lbl_802C2A18 + 0xC6, 0);
                __timesdec(result, &temp, &temp2);
            } else {
                decimal temp2;
                __str2dec(&temp2, lbl_802C2A18 + 0xC2, -1);
                __timesdec(result, &temp, &temp2);
            }
        }
    }
}

void __num2dec_internal(decimal* d, double x) {
    char sign = (char)(signbit(x) != 0);

    if (lbl_803E7930 == x) {
        d->sign = sign;
        d->exp = 0;
        d->sig.length = 1;
        d->sig.text[0] = 0;
        return;
    }

    if (!isfinite(x)) {
        d->sign = sign;
        d->exp = 0;
        d->sig.length = 1;
        d->sig.text[0] = fpclassify(x) == 1 ? 'N' : 'I';
        return;
    }

    if (sign != 0) {
        x = -x;
    }

    {
        int exp;
        double frac = frexp(x, &exp);
        short num_bits_extract = DBL_MANT_DIG - __count_trailing_zero(frac);
        double integer;
        decimal int_d, pow2_d;

        __two_exp(&pow2_d, exp - num_bits_extract);
        frac = modf(ldexp(frac, num_bits_extract), &integer);
        __ull2dec(&int_d, (unsigned long long)integer);
        __timesdec(d, &int_d, &pow2_d);
        d->sign = sign;
    }
}

static inline int __must_round(const decimal* d, int digits) {
    unsigned char const* i = d->sig.text + digits;

    if (*i > 5) {
        return 1;
    }

    if (*i < 5) {
        return -1;
    }

    for (i++; i < d->sig.text + d->sig.length; i++) {
        if (*i != 0) {
            return 1;
        }
    }

    if (d->sig.text[digits - 1] & 1) {
        return 1;
    }

    return -1;
}

static inline void __rounddec(decimal* d, int digits) {
    if (digits > 0 && digits < d->sig.length) {
        int unkBool = __must_round(d, digits);
        d->sig.length = digits;

        if (unkBool >= 0) {
            __dorounddecup(d, digits);
        }
    }
}

void __num2dec(const decform* form, double x, decimal* d) {
    short digits = form->digits;
    int i;
    __num2dec_internal(d, x);

    if (d->sig.text[0] > 9) {
        return;
    }

    if (digits > SIGDIGLEN) {
        digits = SIGDIGLEN;
    }

    __rounddec(d, digits);

    while (d->sig.length < digits) {
        d->sig.text[d->sig.length++] = 0;
    }

    d->exp -= d->sig.length - 1;

    for (i = 0; i < d->sig.length; i++) {
        d->sig.text[i] += '0';
    }
}
