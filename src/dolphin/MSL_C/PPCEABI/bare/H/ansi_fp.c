#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_fp.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/limits.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/float.h"

static int __count_trailing_zerol(unsigned long x) {
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

static int __count_trailing_zero(double x) {
    unsigned long* l = (unsigned long*)&x;

    if (l[1] != 0) {
        return __count_trailing_zerol(l[1]);
    }

    return (int)(sizeof(unsigned long) * CHAR_BIT + __count_trailing_zerol(l[0] | 0x00100000));
}

static int __must_round(const decimal* d, int digits) {
    unsigned char const* i = d->sig.text + digits;

    if (*i > 5) {
        return 1;
    }

    if (*i < 5) {
        return -1;
    }

    {
        unsigned char const* e = d->sig.text + d->sig.length;

        for (i++; i < e; i++) {
            if (*i != 0) {
                return 1;
            }
        }
    }

    if (d->sig.text[digits - 1] & 1) {
        return 1;
    }

    return -1;
}

static void __dorounddecup(decimal* d, int digits) {
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

static void __rounddec(decimal* d, int digits) {
    if (digits > 0 && digits < d->sig.length) {
        int unkBool = __must_round(d, digits);
        d->sig.length = digits;

        if (unkBool >= 0) {
            __dorounddecup(d, digits);
        }
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
    unsigned char* ip = mantissa + i + 1;
    unsigned char* ep = ip;
    int y_length = y->sig.length;
    int x_length = x->sig.length;

    result->sign = 0;

    for (; i > 0; i--) {
        int k = y_length - 1;
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
        t = x_length - j;

        if (l > t)
            l = t;

        for (; l > 0; l--, jp++, kp--) {
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

    for (i = 0; i < SIGDIGLEN && ip < ep; i++, ip++) {
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

asm void __str2dec(decimal* d, const char* s, short exp) {
    nofralloc
    sth r5, 0x2(r3)
    li r0, 0x0
    li r6, 0x0
    stb r0, 0x0(r3)
    b _s2d_1
_s2d_0:
    lbz r5, 0x0(r4)
    addi r0, r6, 0x5
    addi r4, r4, 0x1
    addi r6, r6, 0x1
    subi r5, r5, 0x30
    stbx r5, r3, r0
_s2d_1:
    cmpwi r6, 0x24
    bge _s2d_2
    lbz r0, 0x0(r4)
    extsb. r0, r0
    bne _s2d_0
_s2d_2:
    stb r6, 0x4(r3)
    lbz r5, 0x0(r4)
    extsb. r0, r5
    beqlr
    extsb r0, r5
    cmpwi r0, 0x5
    bltlr
    addi r5, r4, 0x1
    b _s2d_4
_s2d_3:
    extsb r0, r4
    cmpwi r0, 0x30
    bne _s2d_5
    addi r5, r5, 0x1
_s2d_4:
    lbz r4, 0x0(r5)
    extsb. r0, r4
    bne _s2d_3
    add r4, r3, r6
    lbz r0, 0x4(r4)
    clrlwi. r0, r0, 31
    beqlr
_s2d_5:
    lbz r4, 0x4(r3)
    addi r6, r3, 0x5
    li r0, 0x0
    subi r5, r4, 0x1
    add r5, r6, r5
_s2d_6:
    lbz r4, 0x0(r5)
    cmplwi r4, 0x9
    bge _s2d_7
    addi r0, r4, 0x1
    stb r0, 0x0(r5)
    blr
_s2d_7:
    cmplw r5, r6
    bne _s2d_8
    li r0, 0x1
    stb r0, 0x0(r5)
    lha r4, 0x2(r3)
    addi r0, r4, 0x1
    sth r0, 0x2(r3)
    blr
_s2d_8:
    stb r0, 0x0(r5)
    subi r5, r5, 0x1
    b _s2d_6
    blr
}

static const char* const unused = "179769313486231580793729011405303420";

extern const char lbl_802C3198[];
extern void* jumptable_80333120[];

asm void __two_exp(decimal* result, long exp) {
    nofralloc
    stwu r1, -0xd0(r1)
    mflr r0
    stw r0, 0xd4(r1)
    stw r31, 0xcc(r1)
    mr r31, r3
    stw r30, 0xc8(r1)
    stw r29, 0xc4(r1)
    mr r29, r4
    extsh r30, r29
    addi r0, r30, 0x40
    cmplwi r0, 0x48
    bgt _te_0
    lis r4, jumptable_80333120@ha
    slwi r0, r0, 2
    addi r4, r4, jumptable_80333120@l
    lwzx r0, r4, r0
    mtctr r0
    bctr
    lis r4, lbl_802C3198@ha
    li r5, -0x14
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0x25
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x10
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0x53
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0xa
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0x7a
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x5
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0x92
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x3
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0x9f
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x3
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xa6
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x2
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xac
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x2
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xb2
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x2
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xb7
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xbb
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xbf
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, -0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xc2
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x0
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xc4
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x0
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xc6
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x0
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xc8
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x0
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xca
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xcc
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xcf
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x1
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xd2
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x2
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xd5
    bl __str2dec
    b _te_2
    lis r4, lbl_802C3198@ha
    li r5, 0x2
    addi r4, r4, lbl_802C3198@l
    addi r4, r4, 0xd9
    bl __str2dec
    b _te_2
_te_0:
    srwi r0, r30, 31
    addi r3, r1, 0x8c
    add r0, r0, r30
    srawi r0, r0, 1
    extsh r4, r0
    bl __two_exp
    addi r4, r1, 0x8c
    mr r3, r31
    mr r5, r4
    bl __timesdec
    clrlwi. r0, r30, 31
    beq _te_2
    lwz r3, 0x0(r31)
    extsh. r0, r29
    lwz r0, 0x4(r31)
    stw r3, 0x60(r1)
    stw r0, 0x64(r1)
    lwz r3, 0x8(r31)
    lwz r0, 0xc(r31)
    stw r3, 0x68(r1)
    stw r0, 0x6c(r1)
    lwz r3, 0x10(r31)
    lwz r0, 0x14(r31)
    stw r3, 0x70(r1)
    stw r0, 0x74(r1)
    lwz r3, 0x18(r31)
    lwz r0, 0x1c(r31)
    stw r3, 0x78(r1)
    stw r0, 0x7c(r1)
    lwz r3, 0x20(r31)
    lwz r0, 0x24(r31)
    stw r3, 0x80(r1)
    stw r0, 0x84(r1)
    lhz r0, 0x28(r31)
    sth r0, 0x88(r1)
    ble _te_1
    lis r4, lbl_802C3198@ha
    addi r3, r1, 0x34
    addi r4, r4, lbl_802C3198@l
    li r5, 0x0
    addi r4, r4, 0xc6
    bl __str2dec
    mr r3, r31
    addi r4, r1, 0x60
    addi r5, r1, 0x34
    bl __timesdec
    b _te_2
_te_1:
    lis r4, lbl_802C3198@ha
    addi r3, r1, 0x8
    addi r4, r4, lbl_802C3198@l
    li r5, -0x1
    addi r4, r4, 0xc2
    bl __str2dec
    mr r3, r31
    addi r4, r1, 0x60
    addi r5, r1, 0x8
    bl __timesdec
_te_2:
    lwz r0, 0xd4(r1)
    lwz r31, 0xcc(r1)
    lwz r30, 0xc8(r1)
    lwz r29, 0xc4(r1)
    mtlr r0
    addi r1, r1, 0xd0
    blr
}


int __equals_dec(const decimal* x, const decimal* y) {
    if (x->sig.text[0] == 0) {
        if (y->sig.text[0] == 0)
            return 1;
        return 0;
    }
    if (y->sig.text[0] == 0) {
        if (x->sig.text[0] == 0)
            return 1;
        return 0;
    }

    if (x->exp == y->exp) {
        int i;
        int l = x->sig.length;

        if (l > y->sig.length) {
            l = y->sig.length;
        }

        for (i = 0; i < l; i++) {
            if (x->sig.text[i] != y->sig.text[i]) {
                return 0;
            }
        }

        if (l == x->sig.length) {
            for (; i < y->sig.length; ++i) {
                if (y->sig.text[i] != 0) {
                    return 0;
                }
            }
        } else {
            for (; i < x->sig.length; ++i) {
                if (x->sig.text[i] != 0) {
                    return 0;
                }
            }
        }

        return 1;
    }
    return 0;
}

int __less_dec(const decimal* x, const decimal* y) {
    if (x->sig.text[0] == 0) {
        if (y->sig.text[0] != 0)
            return 1;
        return 0;
    }

    if (y->sig.text[0] == 0) {
        return 0;
    }

    if (x->exp == y->exp) {
        int i;
        int l = x->sig.length;

        if (l > y->sig.length) {
            l = y->sig.length;
        }

        for (i = 0; i < l; i++) {
            if (x->sig.text[i] < y->sig.text[i]) {
                return 1;
            } else if (y->sig.text[i] < x->sig.text[i]) {
                return 0;
            }
        }

        if (l == x->sig.length) {
            for (; i < y->sig.length; i++) {
                if (y->sig.text[i] != 0) {
                    return 1;
                }
            }
        }
        return 0;
    }

    return x->exp < y->exp;
}

void __minus_dec(decimal* z, const decimal* x, const decimal* y) {
    int zlen, dexp;
    unsigned char *ib, *i, *ie;
    unsigned char const *jb, *j, *jn;

    *z = *x;

    if (y->sig.text[0] == 0)
        return;

    zlen = z->sig.length;
    if (zlen < y->sig.length)
        zlen = y->sig.length;

    dexp = z->exp - y->exp;
    zlen += dexp;

    if (zlen > SIGDIGLEN)
        zlen = SIGDIGLEN;

    while (z->sig.length < zlen) {
        z->sig.text[z->sig.length++] = 0;
    }

    ib = z->sig.text;
    i = ib + zlen;

    if (y->sig.length + dexp < zlen) {
        i = ib + (y->sig.length + dexp);
    }

    jb = y->sig.text;
    j = jb + (i - ib - dexp);
    jn = j;

    while (i > ib && j > jb) {
        i--;
        j--;
        if (*i < *j) {
            unsigned char* k = i - 1;
            while (*k == 0)
                k--;
            while (k != i) {
                --*k;
                *++k += 10;
            }
        }
        *i -= *j;
    }

    if (jn - jb < y->sig.length) {
        int round_down = 0;
        if (*jn < 5)
            round_down = 1;
        else if (*jn == 5) {
            unsigned char const* ibPtr = y->sig.text + y->sig.length;

            for (j = jn + 1; j < ibPtr; j++) {
                if (*j != 0)
                    goto done;
            }
            i = ib + (jn - jb) + dexp - 1;
            if (*i & 1)
                round_down = 1;
        }
        if (round_down) {
            if (*i < 1) {
                unsigned char* k = i - 1;
                while (*k == 0)
                    k--;
                while (k != i) {
                    --*k;
                    *++k += 10;
                }
            }
            *i -= 1;
        }
    }
done:
    for (i = ib; *i == 0; ++i) {
    }

    if (i > ib) {
        unsigned char dl = (unsigned char)(i - ib);
        z->exp -= dl;
        ie = ib + z->sig.length;
        for (; i < ie; ++i, ++ib)
            *ib = *i;
        z->sig.length -= dl;
    }

    ib = z->sig.text;
    for (i = ib + z->sig.length; i > ib;) {
        i--;
        if (*i != 0)
            break;
    }
    z->sig.length = (unsigned char)(i - ib + 1);
}

void __num2dec_internal(decimal* d, double x) {
    signed char sign = (signed char)(signbit(x) != 0);

    if (x == 0) {
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
        d->sig.text[0] = isnan(x)? 'N' : 'I';
        return;
    }

    if (sign != 0) {
        x = -x;
    }

    {
        int exp;
        double frac = frexp(x, &exp);
        long num_bits_extract = DBL_MANT_DIG - __count_trailing_zero(frac);
        double integer;
        decimal int_d, pow2_d;

        __two_exp(&pow2_d, exp - num_bits_extract);
        frac = modf(ldexp(frac, num_bits_extract), &integer);
        __ull2dec(&int_d, (unsigned long long)integer);
        __timesdec(d, &int_d, &pow2_d);
        d->sign = sign;
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
