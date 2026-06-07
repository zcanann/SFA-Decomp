/*
 * zlbDecompress -- reconstructed GCC reference implementation. NOT IN THE BUILD.
 *
 * STATUS: structurally aligned reference, pending exact-vintage GCC.
 * The retail object is a foreign GCC compile (SN ProDG family), NOT MWCC --
 * see the "Foreign-compiler objects" section in CLAUDE.md for the detection
 * signature and full evidence trail (task #19). Our bundled ProDG 3.5-3.9.3
 * (GCC 2.95.2/3 SN builds) reproduce this source's structure against the
 * retail fn (591 vs 588 instrs, 0.52 mnemonic alignment at -O1, all loop/
 * table/macro shapes aligned); the residual divergence classes are pure
 * compiler vintage (andi. isel for contiguous masks, mcrxr/addme. decrement
 * loops, no lbzux/lhzu fusion, no loop-invariant lis hoisting) and point at
 * a GCC 2.7/2.8-era SN or Cygnus toolchain. Integrating this requires an
 * own-unit split + vintage GCC + custom build rule -- owner-level decision.
 *
 * Probe-verified GCC spellings (do not "clean up"):
 * - The rotate must be spelled (b << m) | (b >> (32 - m)) with m a NAMED
 *   variable/temp -- pre-folded counts (e.g. b >> (8-n) | b << (24+n)) do
 *   NOT pattern-match to rlwnm.
 * - sh is maintained as 32 - pos by ZADV precisely so the rotate idiom has
 *   its count in a variable; the stored-block path resets pos only (sh goes
 *   stale -- faithful to the retail asm, latent bug never hit in practice).
 * - The retail asm reads multi-byte groups src[2],src[1],src[0] (GCC eval
 *   order) and keeps the (rot|s1)|s2 or-tree; per-site loop spellings
 *   (walking pointer vs re-indexed) follow the retail asm per site.
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern u8 lbl_8030C880[];
extern u16 lbl_8030C9A0[];
extern u8 lbl_8030CDA0[];
extern u8 lbl_8030CDC0[];
extern u8 lbl_8030CDE0[];
extern u8 lbl_802C1C50[];
extern u16 lbl_802C1C64[];
extern u16 lbl_802C1CD8[];
extern u8 lbl_803DCD20[];
extern u8 lbl_803DCD18[];
extern u8 lbl_80377880[];
extern u16 lbl_80377894[];
extern u16 lbl_80377954[];
extern u16 lbl_803778B4[];
extern u16 lbl_80377974[];
extern u8 lbl_803778D4[];
extern u8 lbl_8035F740[];
extern u16 lbl_8035F860[];
extern u8 lbl_8036F860[];
extern u8 lbl_8036F880[];

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
                    lbl_80377880[lbl_802C1C50[i]] = v;
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
                    len2 = *(u16 *)((u8 *)lbl_802C1C64 + io);
                    eb = *(u16 *)((u8 *)lbl_802C1C64 + 2 + io);
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
                    dist = *(u16 *)((u8 *)lbl_802C1CD8 + dsym * 4);
                    eb = *(u16 *)((u8 *)lbl_802C1CD8 + 2 + dsym * 4);
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
