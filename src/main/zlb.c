typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

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

u8 lbl_8035F740[0x120];
u16 lbl_8035F860[0x8000];
u8 lbl_8036F860[0x20];
u8 lbl_8036F880[0x8000];
u8 lbl_80377880[0x14];
u16 lbl_80377894[0x10];
u16 lbl_803778B4[0x10];
u8 lbl_803778D4[0x80];
u16 lbl_80377954[0x10];
u16 lbl_80377974[0x16];

u8 lbl_803DCD18[8];
u8 lbl_803DCD20[8];

#define ZROT1(b) ((((u32)(b) << sh) | ((u32)(b) >> (32 - sh))) & 1)
#define ZROT8(b) ((((u32)(b) << sh) | ((u32)(b) >> (32 - sh))) & 0xff)
#define ZGB8() (ZROT8(src[0]) | (u32)src[1] << (8 - pos))
#define ZGB16() (ZROT8(src[0]) | (u32)src[1] << (8 - pos) | (u32)src[2] << (0x10 - pos))
#define ZADV(n) (pos += (n), src += pos >> 3, pos &= 7, sh = 32 - pos)
#define ZROTL(b, m) (((u32)(b) << (m)) | ((u32)(b) >> (32 - (m))))

int zlbDecompress(void *srcv, int size, int dstv, void *outp) {
    u8 *src;
    u8 *dst;
    int pos;
    u8 *lenBitsP;
    u8 *lenTblP;
    int lenMax;
    u8 *distBitsP;
    u8 *distTblP;
    int distMax;
    int sh;
    int hlit;
    int hdist;
    int hclen;
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
    u8 *curLens;
    u8 *curCnt;

    dst = (u8 *)dstv - 1;
    pos = 0;
    sh = 32;
    src = (u8 *)srcv + 2;
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
                lenBitsP = lbl_8030C880;
                lenTblP = (u8 *)lbl_8030C9A0;
                lenMax = 9;
                distBitsP = lbl_8030CDA0;
                distTblP = lbl_8030CDC0;
                distMax = 5;
            } else {
                lenBitsP = lbl_8035F740;
                lenTblP = (u8 *)lbl_8035F860;
                distBitsP = lbl_8036F860;
                distTblP = lbl_8036F880;
                val = 0;
                p8 = lbl_803DCD20;
                for (i = 8; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p8 = lbl_80377880;
                for (i = 0x13; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p16 = lbl_80377894;
                for (i = 0x10; i != 0; i--) {
                    *p16 = val;
                    p16++;
                }
                p8 = lenBitsP;
                for (i = 0x120; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                p16 = lbl_803778B4;
                for (i = 0x10; i != 0; i--) {
                    *p16 = val;
                    p16++;
                }
                p8 = distBitsP;
                for (i = 0x20; i != 0; i--) {
                    *p8 = val;
                    p8++;
                }
                hlit = (ZGB8() & 0x1f) + 0x101;
                ZADV(5);
                hdist = (ZGB8() & 0x1f) + 1;
                ZADV(5);
                hclen = (ZGB8() & 0xf) + 4;
                ZADV(4);
                for (i = 0; i != hclen; i++) {
                    u32 v = ZGB8() & 7;
                    lbl_80377880[gInflateCodeLengthOrder[i]] = v;
                    lbl_803DCD20[v] += 1;
                    ZADV(3);
                }
                lenMax = 7;
                while (lbl_803DCD20[lenMax] == 0) {
                    lenMax--;
                }
                code = 0;
                for (j = 1; j <= lenMax; j++) {
                    if (lbl_803DCD20[j] != 0) {
                        lbl_803DCD18[j] = code;
                        code += lbl_803DCD20[j] << (lenMax - j);
                    }
                }
                for (i = 0; i < 0x13; i++) {
                    u32 len = lbl_80377880[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (lenMax - len); k++) {
                            u8 c = lbl_803DCD18[len] + 1;
                            lbl_803DCD18[len] = c;
                            (lbl_803778D4 - 1)[c] = i;
                        }
                    }
                }
                curLens = lenBitsP;
                curCnt = (u8 *)lbl_80377894;
                n = 0;
                do {
                    u32 extra;
                    u32 v;
                    u32 rep;
                    extra = 0;
                    if (pos > 8 - lenMax) {
                        extra = (u32)src[1] << (8 - pos);
                    }
                    v = (ZROT8(src[0]) | extra) & ((1 << lenMax) - 1);
                    m = lenMax + 0x18;
                    sym = lbl_803778D4[ZROTL(lbl_8030CDE0[v], m) & 0xff];
                    ZADV(lbl_80377880[sym]);
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
                        curLens[n] = val;
                        n += 1;
                        *(u16 *)(curCnt + val + val) += 1;
                        if (curLens == lenBitsP && n == hlit) {
                            curCnt = (u8 *)lbl_803778B4;
                            n = 0;
                            curLens = distBitsP;
                        }
                    } while (--rep != 0);
                } while (curLens == lenBitsP || n < hdist);
                lenMax = 0xf;
                p8 = (u8 *)lbl_80377894 + lenMax + lenMax;
                while (*(u16 *)p8 == 0) {
                    p8 -= 2;
                    lenMax--;
                }
                code = 0;
                for (j = 1; j <= lenMax; j++) {
                    if (*(u16 *)((u8 *)lbl_80377894 + j + j) != 0) {
                        *(u16 *)((u8 *)lbl_80377954 + j + j) = code;
                        code += *(u16 *)((u8 *)lbl_80377894 + j + j) << (lenMax - j);
                    }
                }
                for (i = 0; i < hlit; i++) {
                    u32 len = lenBitsP[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (lenMax - len); k++) {
                            u16 c = *(u16 *)((u8 *)lbl_80377954 + len + len) + 1;
                            *(u16 *)((u8 *)lbl_80377954 + len + len) = c;
                            *(u16 *)(lenTblP + (c - 1) + (c - 1)) = i;
                        }
                    }
                }
                distMax = 0xf;
                while (*(u16 *)((u8 *)lbl_803778B4 + distMax + distMax) == 0) {
                    distMax--;
                }
                code = 0;
                for (j = 1; j <= distMax; j++) {
                    if (*(u16 *)((u8 *)lbl_803778B4 + j + j) != 0) {
                        *(u16 *)((u8 *)lbl_80377974 + j + j) = code;
                        code += *(u16 *)((u8 *)lbl_803778B4 + j + j) << (distMax - j);
                    }
                }
                for (i = 0; i < hdist; i++) {
                    u32 len = distBitsP[i];
                    if (len != 0) {
                        for (k = 0; k < 1 << (distMax - len); k++) {
                            u16 c = *(u16 *)((u8 *)lbl_80377974 + len + len) + 1;
                            *(u16 *)((u8 *)lbl_80377974 + len + len) = c;
                            distTblP[c - 1] = i;
                        }
                    }
                }
            }
            do {
                u32 t;
                u32 code2;
                t = ZGB16() & ((1 << lenMax) - 1);
                m = lenMax - 8;
                code2 = ZROTL(lbl_8030CDE0[t & 0xff], m) & 0xffff;
                m = lenMax + 0x10;
                code2 |= ZROTL(lbl_8030CDE0[t >> 8], m) & 0xff;
                sym = *(u16 *)(lenTblP + code2 + code2);
                ZADV(lenBitsP[sym]);
                if ((int)sym < 0x100) {
                    *++dst = sym;
                } else if (sym != 0x100) {
                    u32 len2;
                    u32 eb;
                    u32 dt;
                    u32 dcode;
                    u32 dsym;
                    u32 dist;
                    int io = (sym - 0x101) * 4;
                    len2 = *(u16 *)((u8 *)gInflateLengthCodes + io);
                    eb = *(u16 *)((u8 *)gInflateLengthCodes + 2 + io);
                    if (eb != 0) {
                        len2 += ZGB8() & ((1 << eb) - 1);
                        ZADV(eb);
                    }
                    dt = ZGB16() & ((1 << distMax) - 1);
                    m = distMax - 8;
                    dcode = ZROTL(lbl_8030CDE0[dt & 0xff], m) & 0xffff;
                    m = distMax + 0x10;
                    dcode |= ZROTL(lbl_8030CDE0[dt >> 8], m) & 0xff;
                    dsym = distTblP[dcode];
                    ZADV(distBitsP[dsym]);
                    dist = *(u16 *)((u8 *)gInflateDistCodes + dsym * 4);
                    eb = *(u16 *)((u8 *)gInflateDistCodes + 2 + dsym * 4);
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
