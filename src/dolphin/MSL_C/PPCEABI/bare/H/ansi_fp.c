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

asm void __timesdec(decimal* result, const decimal* x, const decimal* y) {
    nofralloc
    stwu r1, -0x60(r1)
    li r0, 0x0
    lis r7, 0xcccd
    li r12, 0x0
    stw r31, 0x5c(r1)
    addi r8, r1, 0x8
    stw r30, 0x58(r1)
    stw r29, 0x54(r1)
    lbz r6, 0x4(r5)
    lbz r9, 0x4(r4)
    subi r31, r6, 0x1
    add r31, r9, r31
    stb r0, 0x0(r3)
    addi r6, r31, 0x1
    subi r9, r7, 0x3333
    add r6, r8, r6
    mr r0, r6
    b _td_7
_td_0:
    lbz r7, 0x4(r5)
    subi r8, r7, 0x1
    subf r7, r8, r31
    subic. r10, r7, 0x1
    bge _td_1
    li r10, 0x0
    subi r8, r31, 0x1
_td_1:
    lbz r7, 0x4(r4)
    addi r30, r10, 0x5
    addi r29, r8, 0x5
    addi r8, r8, 0x1
    subf r7, r10, r7
    add r30, r4, r30
    cmpw r8, r7
    add r29, r5, r29
    ble _td_2
    mr r8, r7
_td_2:
    cmpwi r8, 0x0
    ble _td_6
    srwi. r7, r8, 3
    mtctr r7
    beq _td_4
_td_3:
    lbz r11, 0x0(r30)
    lbz r10, 0x0(r29)
    mullw r7, r11, r10
    lbz r11, 0x1(r30)
    lbz r10, -0x1(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x2(r30)
    lbz r10, -0x2(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x3(r30)
    lbz r10, -0x3(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x4(r30)
    lbz r10, -0x4(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x5(r30)
    lbz r10, -0x5(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x6(r30)
    lbz r10, -0x6(r29)
    add r12, r12, r7
    mullw r7, r11, r10
    lbz r11, 0x7(r30)
    lbz r10, -0x7(r29)
    addi r30, r30, 0x8
    subi r29, r29, 0x8
    add r12, r12, r7
    mullw r7, r11, r10
    add r12, r12, r7
    bdnz _td_3
    andi. r8, r8, 0x7
    beq _td_6
_td_4:
    mtctr r8
_td_5:
    lbz r11, 0x0(r30)
    addi r30, r30, 0x1
    lbz r10, 0x0(r29)
    subi r29, r29, 0x1
    mullw r7, r11, r10
    add r12, r12, r7
    bdnz _td_5
_td_6:
    mulhwu r8, r9, r12
    li r7, 0xa
    subi r31, r31, 0x1
    srwi r8, r8, 3
    mulli r8, r8, 0xa
    subf r8, r8, r12
    divwu r12, r12, r7
    stbu r8, -0x1(r6)
_td_7:
    cmpwi r31, 0x0
    bgt _td_0
    lha r7, 0x2(r4)
    cmplwi r12, 0x0
    lha r4, 0x2(r5)
    add r4, r7, r4
    sth r4, 0x2(r3)
    beq _td_8
    stbu r12, -0x1(r6)
    lha r4, 0x2(r3)
    addi r4, r4, 0x1
    sth r4, 0x2(r3)
_td_8:
    li r7, 0x0
    b _td_10
_td_9:
    lbz r5, 0x0(r6)
    addi r4, r7, 0x5
    addi r7, r7, 0x1
    addi r6, r6, 0x1
    stbx r5, r3, r4
_td_10:
    cmpwi r7, 0x24
    bge _td_11
    cmplw r6, r0
    blt _td_9
_td_11:
    cmplw r6, r0
    stb r7, 0x4(r3)
    bge _td_18
    lbz r4, 0x0(r6)
    cmplwi r4, 0x5
    blt _td_18
    bne _td_14
    addi r5, r6, 0x1
    subf r4, r5, r0
    mtctr r4
    cmplw r5, r0
    bge _td_13
_td_12:
    lbz r0, 0x0(r5)
    cmplwi r0, 0x0
    bne _td_14
    addi r5, r5, 0x1
    bdnz _td_12
_td_13:
    lbz r0, -0x1(r6)
    clrlwi. r0, r0, 31
    beq _td_18
_td_14:
    lbz r4, 0x4(r3)
    addi r6, r3, 0x5
    li r0, 0x0
    subi r5, r4, 0x1
    add r5, r6, r5
_td_15:
    lbz r4, 0x0(r5)
    cmplwi r4, 0x9
    bge _td_16
    addi r0, r4, 0x1
    stb r0, 0x0(r5)
    b _td_18
_td_16:
    cmplw r5, r6
    bne _td_17
    li r0, 0x1
    stb r0, 0x0(r5)
    lha r4, 0x2(r3)
    addi r0, r4, 0x1
    sth r0, 0x2(r3)
    b _td_18
_td_17:
    stb r0, 0x0(r5)
    subi r5, r5, 0x1
    b _td_15
_td_18:
    lwz r31, 0x5c(r1)
    lwz r30, 0x58(r1)
    lwz r29, 0x54(r1)
    addi r1, r1, 0x60
    blr
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

extern const double lbl_803E85C8;
extern void __cvt_dbl_usll(double);

asm void __num2dec_internal(decimal* d, double x) {
    nofralloc
    stwu r1, -0xb0(r1)
    mflr r0
    lfd f0, lbl_803E85C8(r2)
    stw r0, 0xb4(r1)
    fcmpu cr0, f0, f1
    stfd f31, 0xa8(r1)
    stw r31, 0xa4(r1)
    stw r30, 0xa0(r1)
    mr r30, r3
    stfd f1, 0x8(r1)
    lwz r0, 0x8(r1)
    stw r29, 0x9c(r1)
    srwi r0, r0, 31
    extsb r31, r0
    bne _n2_0
    stb r31, 0x0(r30)
    li r3, 0x0
    li r0, 0x1
    sth r3, 0x2(r30)
    stb r0, 0x4(r30)
    stb r3, 0x5(r30)
    b _n2_22
_n2_0:
    stfd f1, 0x28(r1)
    lis r0, 0x7ff0
    lwz r4, 0x28(r1)
    rlwinm r3, r4, 0, 1, 11
    cmpw r3, r0
    beq _n2_1
    bge _n2_7
    cmpwi r3, 0x0
    beq _n2_4
    b _n2_7
_n2_1:
    clrlwi. r0, r4, 12
    bne _n2_2
    lwz r0, 0x2c(r1)
    cmpwi r0, 0x0
    beq _n2_3
_n2_2:
    li r0, 0x1
    b _n2_8
_n2_3:
    li r0, 0x2
    b _n2_8
_n2_4:
    clrlwi. r0, r4, 12
    bne _n2_5
    lwz r0, 0x2c(r1)
    cmpwi r0, 0x0
    beq _n2_6
_n2_5:
    li r0, 0x5
    b _n2_8
_n2_6:
    li r0, 0x3
    b _n2_8
_n2_7:
    li r0, 0x4
_n2_8:
    cmpwi r0, 0x2
    bgt _n2_18
    lfd f0, 0x8(r1)
    li r3, 0x0
    stb r31, 0x0(r30)
    lis r0, 0x7ff0
    li r4, 0x1
    stfd f0, 0x20(r1)
    lwz r5, 0x20(r1)
    sth r3, 0x2(r30)
    rlwinm r3, r5, 0, 1, 11
    cmpw r3, r0
    stb r4, 0x4(r30)
    beq _n2_9
    bge _n2_15
    cmpwi r3, 0x0
    beq _n2_12
    b _n2_15
_n2_9:
    clrlwi. r0, r5, 12
    bne _n2_10
    lwz r0, 0x24(r1)
    cmpwi r0, 0x0
    beq _n2_11
_n2_10:
    li r0, 0x1
    b _n2_16
_n2_11:
    li r0, 0x2
    b _n2_16
_n2_12:
    clrlwi. r0, r5, 12
    bne _n2_13
    lwz r0, 0x24(r1)
    cmpwi r0, 0x0
    beq _n2_14
_n2_13:
    li r0, 0x5
    b _n2_16
_n2_14:
    li r0, 0x3
    b _n2_16
_n2_15:
    li r0, 0x4
_n2_16:
    cmpwi r0, 0x1
    li r0, 0x49
    bne _n2_17
    li r0, 0x4e
_n2_17:
    stb r0, 0x5(r30)
    b _n2_22
_n2_18:
    extsb. r0, r31
    beq _n2_19
    fneg f0, f1
    stfd f0, 0x8(r1)
_n2_19:
    lfd f1, 0x8(r1)
    addi r3, r1, 0x10
    bl frexp
    fmr f31, f1
    stfd f31, 0x18(r1)
    lwz r3, 0x1c(r1)
    cmplwi r3, 0x0
    beq _n2_20
    bl __count_trailing_zerol
    b _n2_21
_n2_20:
    lwz r0, 0x18(r1)
    oris r3, r0, 0x10
    bl __count_trailing_zerol
    addi r3, r3, 0x20
_n2_21:
    subfic r3, r3, 0x35
    lwz r0, 0x10(r1)
    extsh r29, r3
    subf r0, r29, r0
    addi r3, r1, 0x38
    extsh r4, r0
    bl __two_exp
    fmr f1, f31
    mr r3, r29
    bl ldexp
    addi r3, r1, 0x30
    bl modf
    lfd f1, 0x30(r1)
    bl __cvt_dbl_usll
    mr r5, r3
    mr r6, r4
    addi r3, r1, 0x64
    bl __ull2dec
    mr r3, r30
    addi r4, r1, 0x64
    addi r5, r1, 0x38
    bl __timesdec
    stb r31, 0x0(r30)
_n2_22:
    lwz r0, 0xb4(r1)
    lfd f31, 0xa8(r1)
    lwz r31, 0xa4(r1)
    lwz r30, 0xa0(r1)
    lwz r29, 0x9c(r1)
    mtlr r0
    addi r1, r1, 0xb0
    blr
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
