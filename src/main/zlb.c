typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#include "main/zlb.h"

typedef struct {
    u16 base;
    u16 extra;
} InflateBaseExtra;

const u8 gInflateCodeLengthOrder[20] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15, 0};
const InflateBaseExtra gInflateLengthCodes[29] = {
    {3, 0},   {4, 0},   {5, 0},   {6, 0},   {7, 0},   {8, 0},   {9, 0},   {10, 0},
    {11, 1},  {13, 1},  {15, 1},  {17, 1},  {19, 2},  {23, 2},  {27, 2},  {31, 2},
    {35, 3},  {43, 3},  {51, 3},  {59, 3},  {67, 4},  {83, 4},  {99, 4},  {115, 4},
    {131, 5}, {163, 5}, {195, 5}, {227, 5}, {258, 0}};
const InflateBaseExtra gInflateDistCodes[30] = {
    {1, 0},     {2, 0},     {3, 0},     {4, 0},     {5, 1},     {7, 1},
    {9, 2},     {13, 2},    {17, 3},    {25, 3},    {33, 4},    {49, 4},
    {65, 5},    {97, 5},    {129, 6},   {193, 6},   {257, 7},   {385, 7},
    {513, 8},   {769, 8},   {1025, 9},  {1537, 9},  {2049, 10}, {3073, 10},
    {4097, 11}, {6145, 11}, {8193, 12}, {12289, 12}, {16385, 13}, {24577, 13}};

extern u8 lbl_8030C880[];
extern u16 lbl_8030C9A0[];
extern u8 lbl_8030CDA0[];
extern u8 lbl_8030CDC0[];
extern u8 lbl_8030CDE0[];

u8 gInflateLiteralCodeLengths[0x120];
u16 gInflateLiteralDecodeTable[0x8000];
u8 gInflateDistanceCodeLengths[0x20];
u8 gInflateDistanceDecodeTable[0x8000];
u8 gInflateCodeLengthCodeLengths[0x14];
u16 gInflateLiteralLengthCounts[0x10];
u16 gInflateDistanceLengthCounts[0x10];
u8 gInflateCodeLengthDecodeTable[0x80];
u16 gInflateLiteralNextCode[0x10];
u16 gInflateDistanceNextCode[0x16];

u8 lbl_803DCD18[8];
u8 lbl_803DCD20[8];

#define ZROT1(b) ((((u32)(b) << sh) | ((u32)(b) >> (32 - sh))) & 1)
#define ZROT8(b) ((((u32)(b) << sh) | ((u32)(b) >> (32 - sh))) & 0xff)
#define ZGB8() (ZROT8(src[0]) | (u32)src[1] << (8 - pos))
#define ZGB16() (ZROT8(src[0]) | (u32)src[1] << (8 - pos) | (u32)src[2] << (0x10 - pos))
#define ZADV(n) (pos += (n), src += pos >> 3, pos &= 7, sh = 32 - pos)
#define ZROTL(b, m) (((u32)(b) << (m)) | ((u32)(b) >> (32 - (m))))

int zlbDecompress(u8 *srcv, int size, u8 *dstv, void *outp) {
    u8 *src;
    u8 *dst;
    int pos;
    u8 *literalCodeLengths;
    u8 *literalDecodeTable;
    int literalMaxBits;
    u8 *distanceCodeLengths;
    u8 *distanceDecodeTable;
    int distanceMaxBits;
    int sh;
    int literalCodeCount;
    int distanceCodeCount;
    int codeLengthCodeCount;
    u32 final;
    u32 type;
    u32 sym;
    u32 code;
    u32 val;
    int i;
    int j;
    int k;
    int m;
    int n;
    u8 *p8;
    u16 *p16;
    u8 *activeCodeLengths;
    u8 *activeLengthCounts;

    dst = dstv - 1;
    pos = 0;
    sh = 32;
    src = srcv + 2;
    do {
        final = ZROT1(src[0]);
        ZADV(1);
        type = ZGB8() & 3;
        ZADV(2);
        if (type == 0) {
            u32 len;
            if (pos != 0) {
                src += 1;
                pos = 0;
            }
            len = *(u16 *)src;
            src += 1;
            len |= (u32)*(u16 *)src << 8;
            src += 3;
            do {
                u8 v = *src;
                src += 1;
                *++dst = v;
            } while (len-- != 0);
        } else {
            if (type == 1) {
                literalCodeLengths = lbl_8030C880;
                literalDecodeTable = (u8 *)lbl_8030C9A0;
                literalMaxBits = 9;
                distanceCodeLengths = lbl_8030CDA0;
                distanceDecodeTable = lbl_8030CDC0;
                distanceMaxBits = 5;
            } else {
                literalCodeLengths = gInflateLiteralCodeLengths;
                literalDecodeTable = (u8 *)gInflateLiteralDecodeTable;
                distanceCodeLengths = gInflateDistanceCodeLengths;
                distanceDecodeTable = gInflateDistanceDecodeTable;
                val = 0;
                p8 = lbl_803DCD20;
                for (i = 8; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p8 = gInflateCodeLengthCodeLengths;
                for (i = 0x13; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p16 = gInflateLiteralLengthCounts;
                for (i = 0x10; i != 0; i--) {
                    *p16 = val;
                    p16++;
                }
                p8 = literalCodeLengths;
                for (i = 0x120; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p16 = gInflateDistanceLengthCounts;
                for (i = 0x10; i != 0; i--) {
                    *p16 = val;
                    p16++;
                }
                p8 = distanceCodeLengths;
                for (i = 0x20; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                literalCodeCount = (ZGB8() & 0x1f) + 0x101;
                ZADV(5);
                distanceCodeCount = (ZGB8() & 0x1f) + 1;
                ZADV(5);
                codeLengthCodeCount = (ZGB8() & 0xf) + 4;
                ZADV(4);
                for (i = 0; i != codeLengthCodeCount; i++) {
                    u32 v = ZGB8() & 7;
                    gInflateCodeLengthCodeLengths[gInflateCodeLengthOrder[i]] = v;
                    lbl_803DCD20[v] += 1;
                    ZADV(3);
                }
                literalMaxBits = 7;
                while (lbl_803DCD20[literalMaxBits] == 0) {
                    literalMaxBits--;
                }
                code = 0;
                for (j = 1; j <= literalMaxBits; j++) {
                    if (lbl_803DCD20[j] != 0) {
                        lbl_803DCD18[j] = code;
                        code += lbl_803DCD20[j] << (literalMaxBits - j);
                    }
                }
                for (i = 0; i < 0x13; i++) {
                    u32 len = gInflateCodeLengthCodeLengths[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (literalMaxBits - len); k++) {
                            u8 c = lbl_803DCD18[len] + 1;
                            lbl_803DCD18[len] = c;
                            (gInflateCodeLengthDecodeTable - 1)[c] = i;
                        }
                    }
                }
                activeCodeLengths = literalCodeLengths;
                activeLengthCounts = (u8 *)gInflateLiteralLengthCounts;
                n = 0;
                do {
                    u32 extra;
                    u32 v;
                    u32 rep;
                    extra = 0;
                    if (pos > 8 - literalMaxBits) {
                        extra = (u32)src[1] << (8 - pos);
                    }
                    v = (ZROT8(src[0]) | extra) & ((1 << literalMaxBits) - 1);
                    m = literalMaxBits + 0x18;
                    sym = gInflateCodeLengthDecodeTable[ZROTL(lbl_8030CDE0[v], m) & 0xff];
                    ZADV(gInflateCodeLengthCodeLengths[sym]);
                    if (sym == 0x10) {
                        rep = (ZGB8() & 3) + 3;
                        ZADV(2);
                    } else if (sym == 0x11) {
                        val = 0;
                        rep = (ZGB8() & 7) + 3;
                        ZADV(3);
                    } else if (sym == 0x12) {
                        val = 0;
                        rep = (ZGB8() & 0x7f) + 0xb;
                        ZADV(7);
                    } else {
                        val = sym;
                        rep = 1;
                    }
                    do {
                        activeCodeLengths[n] = val;
                        n += 1;
                        *(u16 *)(activeLengthCounts + val + val) += 1;
                        if (activeCodeLengths == literalCodeLengths && n == literalCodeCount) {
                            activeLengthCounts = (u8 *)gInflateDistanceLengthCounts;
                            n = 0;
                            activeCodeLengths = distanceCodeLengths;
                        }
                    } while (--rep != 0);
                } while (activeCodeLengths == literalCodeLengths || n < distanceCodeCount);
                literalMaxBits = 0xf;
                p8 = (u8 *)gInflateLiteralLengthCounts + literalMaxBits + literalMaxBits;
                while (*(u16 *)p8 == 0) {
                    p8 -= 2;
                    literalMaxBits--;
                }
                code = 0;
                for (j = 1; j <= literalMaxBits; j++) {
                    if (gInflateLiteralLengthCounts[j] != 0) {
                        gInflateLiteralNextCode[j] = code;
                        code += gInflateLiteralLengthCounts[j] << (literalMaxBits - j);
                    }
                }
                for (i = 0; i < literalCodeCount; i++) {
                    u32 len = literalCodeLengths[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (literalMaxBits - len); k++) {
                            u16 c = gInflateLiteralNextCode[len] + 1;
                            gInflateLiteralNextCode[len] = c;
                            *(u16 *)(literalDecodeTable + (c - 1) + (c - 1)) = i;
                        }
                    }
                }
                distanceMaxBits = 0xf;
                while (gInflateDistanceLengthCounts[distanceMaxBits] == 0) {
                    distanceMaxBits--;
                }
                code = 0;
                for (j = 1; j <= distanceMaxBits; j++) {
                    if (gInflateDistanceLengthCounts[j] != 0) {
                        gInflateDistanceNextCode[j] = code;
                        code += gInflateDistanceLengthCounts[j] << (distanceMaxBits - j);
                    }
                }
                for (i = 0; i < distanceCodeCount; i++) {
                    u32 len = distanceCodeLengths[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (distanceMaxBits - len); k++) {
                            u16 c = gInflateDistanceNextCode[len] + 1;
                            gInflateDistanceNextCode[len] = c;
                            distanceDecodeTable[c - 1] = i;
                        }
                    }
                }
            }
            do {
                u32 t;
                u32 code2;
                t = ZGB16() & ((1 << literalMaxBits) - 1);
                m = literalMaxBits - 8;
                code2 = ZROTL(lbl_8030CDE0[t & 0xff], m) & 0xffff;
                m = literalMaxBits + 0x10;
                code2 |= ZROTL(lbl_8030CDE0[t >> 8], m) & 0xff;
                sym = *(u16 *)(literalDecodeTable + code2 + code2);
                ZADV(literalCodeLengths[sym]);
                if ((int)sym < 0x100) {
                    *++dst = sym;
                } else if (sym != 0x100) {
                    u32 len2;
                    u32 eb;
                    u32 dt;
                    u32 dcode;
                    u32 dsym;
                    u32 dist;
                    len2 = gInflateLengthCodes[sym - 0x101].base;
                    eb = gInflateLengthCodes[sym - 0x101].extra;
                    if (eb != 0) {
                        len2 += ZGB8() & ((1 << eb) - 1);
                        ZADV(eb);
                    }
                    dt = ZGB16() & ((1 << distanceMaxBits) - 1);
                    m = distanceMaxBits - 8;
                    dcode = ZROTL(lbl_8030CDE0[dt & 0xff], m) & 0xffff;
                    m = distanceMaxBits + 0x10;
                    dcode |= ZROTL(lbl_8030CDE0[dt >> 8], m) & 0xff;
                    dsym = distanceDecodeTable[dcode];
                    ZADV(distanceCodeLengths[dsym]);
                    dist = gInflateDistCodes[dsym].base;
                    eb = gInflateDistCodes[dsym].extra;
                    if (eb != 0) {
                        dist += ZGB16() & ((1 << eb) - 1);
                        ZADV(eb);
                    }
                    {
                        u8 *from = dst - dist;
                        do {
                            *++dst = *++from;
                        } while (--len2 != 0);
                    }
                }
            } while (sym != 0x100);
        }
    } while (final == 0);
    return 0;
}
