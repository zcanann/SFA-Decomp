#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

#define SOME_SET_REG_MACRO(reg, size, shift, val)                                                   \
	do {                                                                                            \
		(reg) = (u32)__rlwimi((u32)(reg), (val), (shift), (32 - (shift) - (size)), (31 - (shift))); \
	} while (0);

void GXSetFog(GXFogType type, f32 startz, f32 endz, f32 nearz, f32 farz, GXColor color) {
    u32 fogclr;
    u32 fog0;
    u32 fog1;
    u32 fog2;
    u32 fog3;
    f32 A;
    f32 B;
    f32 B_mant;
    f32 C;
    f32 a;
    f32 c;
    u32 B_expn;
    u32 b_m;
    u32 b_s;
    u32 a_hex;
    u32 c_hex;
    u32 fsel;
    u32 proj;

    fog1 = 0;
    fog2 = 0;

    CHECK_GXBEGIN(138, "GXSetFog");

    ASSERTMSGLINE(140, farz >= 0.0f, "GXSetFog: The farz should be positive value");
    ASSERTMSGLINE(141, farz >= nearz, "GXSetFog: The farz should be larger than nearz");

    fsel = type & 7;
    proj = (type >> 3) & 1;
    
    if (proj) {
        if (farz == nearz || endz == startz) {
            a = 0.0f;
            c = 0.0f;
        } else {
            A = (1.0f / (endz - startz));
            a = A * (farz - nearz);
            c = A * (startz - nearz);
        }
    } else {
        if (farz == nearz || endz == startz) {
            A = 0.0f;
            B = 0.5f;
            C = 0.0f;
        } else {
            A = (farz * nearz) / ((farz - nearz) * (endz - startz));
            B = farz / (farz - nearz);
            C = startz / (endz - startz);
        }

        B_mant = B;
        B_expn = 0;
        while (B_mant > 1.0) {
            B_mant /= 2.0f;
            B_expn++;
        }
        while (B_mant > 0.0f && B_mant < 0.5) {
            B_mant *= 2.0f;
            B_expn--;
        }

        a = A / (f32) (1 << (B_expn + 1));
        b_m = 8388638.0f * B_mant;
        b_s = B_expn + 1;
        c = C;

        fog1 = (b_m & 0x00FFFFFF) | 0xEF000000;
        fog2 = (b_s & 0x00FFFFFF) | 0xF0000000;
    }

    a_hex = *(u32*)&a;
    c_hex = *(u32*)&c;

    fog0 = 0;
    SET_REG_FIELD(0, fog0, 11, 0, (a_hex >> 12) & 0x7FF);
    SET_REG_FIELD(0, fog0, 8, 11, (a_hex >> 23) & 0xFF);
    SET_REG_FIELD(0, fog0, 1, 19, (a_hex >> 31));
    SET_REG_FIELD(0, fog0, 8, 24, 0xEE);

    fog3 = 0;
    SET_REG_FIELD(0, fog3, 11, 0, (c_hex >> 12) & 0x7FF);
    SET_REG_FIELD(0, fog3, 8, 11, (c_hex >> 23) & 0xFF);
    SET_REG_FIELD(0, fog3, 1, 19, (c_hex >> 31));
    SET_REG_FIELD(0, fog3, 1, 20, proj);
    SET_REG_FIELD(0, fog3, 3, 21, fsel);
    SET_REG_FIELD(0, fog3, 8, 24, 0xF1);

    fogclr = 0;
    SET_REG_FIELD(0, fogclr, 8, 0, color.b);
    SET_REG_FIELD(0, fogclr, 8, 8, color.g);
    SET_REG_FIELD(0, fogclr, 8, 16, color.r);
    SET_REG_FIELD(0, fogclr, 8, 24, 0xF2);

    GX_WRITE_RAS_REG(fog0);
    GX_WRITE_RAS_REG(fog1);
    GX_WRITE_RAS_REG(fog2);
    GX_WRITE_RAS_REG(fog3);
    GX_WRITE_RAS_REG(fogclr);

    __GXData->bpSentNot = 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXSetFogRangeAdj(GXBool enable, u16 center, const GXFogAdjTable *table) {
    u32 i;
    u32 fogRangeRegK;
    u32 fogRangeReg;

    CHECK_GXBEGIN(331, "GXSetFogRangeAdj");

    if (enable) {
        ASSERTMSGLINE(334, table != NULL, "GXSetFogRangeAdj: table pointer is null");
        for (i = 0; i < 10; i += 2) {
            fogRangeRegK = 0;
            SET_REG_FIELD(0, fogRangeRegK, 12, 0, table->r[i]);
            SET_REG_FIELD(0, fogRangeRegK, 12, 12, table->r[i + 1]);
            SET_REG_FIELD(0, fogRangeRegK, 8, 24, (i >> 1) + 0xE9);
            GX_WRITE_RAS_REG(fogRangeRegK);
        }
    }

    fogRangeReg = 0;
    SET_REG_FIELD(0, fogRangeReg, 10, 0, center + 342);
    SET_REG_FIELD(0, fogRangeReg, 1, 10, enable);
    SET_REG_FIELD(0, fogRangeReg, 8, 24, 0xE8);
    GX_WRITE_RAS_REG(fogRangeReg);
    __GXData->bpSentNot = 0;
}

void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op) {
    u32 reg;
    u32 blend_en;

    CHECK_GXBEGIN(375, "GXSetBlendMode");

    reg = __GXData->cmode0;

#if DEBUG
    blend_en = type == GX_BM_BLEND || type == GX_BM_SUBTRACT;
#endif

    SOME_SET_REG_MACRO(reg, 1, 11, (type == GX_BM_SUBTRACT));
#if DEBUG
    SOME_SET_REG_MACRO(reg, 1, 0, blend_en);
#else
    SOME_SET_REG_MACRO(reg, 1, 0, type);
#endif
    SOME_SET_REG_MACRO(reg, 1, 1, (type == GX_BM_LOGIC));
    SOME_SET_REG_MACRO(reg, 4, 12, op);
    SOME_SET_REG_MACRO(reg, 3, 8, src_factor);
    SOME_SET_REG_MACRO(reg, 3, 5, dst_factor);
    GX_WRITE_RAS_REG(reg);

    __GXData->cmode0 = reg;
    __GXData->bpSentNot = 0;
}

void GXSetColorUpdate(GXBool update_enable) {
    u32 reg;
    CHECK_GXBEGIN(419, "GXSetColorUpdate");

    reg = __GXData->cmode0;

    SOME_SET_REG_MACRO(reg, 1, 3, update_enable);
    GX_WRITE_RAS_REG(reg);

    __GXData->cmode0 = reg;
    __GXData->bpSentNot = 0;
}

void GXSetAlphaUpdate(GXBool update_enable) {
    u32 reg;
    CHECK_GXBEGIN(432, "GXSetAlphaUpdate");

    reg = __GXData->cmode0;

    SOME_SET_REG_MACRO(reg, 1, 4, update_enable);
    GX_WRITE_RAS_REG(reg);

    __GXData->cmode0 = reg;
    __GXData->bpSentNot = 0;
}

void GXSetZMode(GXBool compare_enable, GXCompare func, GXBool update_enable) {
    u32 reg;
    CHECK_GXBEGIN(459, "GXSetZMode");

    reg = __GXData->zmode;

    SOME_SET_REG_MACRO(reg, 1, 0, compare_enable);
    SOME_SET_REG_MACRO(reg, 3, 1, func);
    SOME_SET_REG_MACRO(reg, 1, 4, update_enable);
    GX_WRITE_RAS_REG(reg);

    __GXData->zmode = reg;
    __GXData->bpSentNot = 0;
}

void GXSetZCompLoc(GXBool before_tex) {
    GXData *gxData;

    CHECK_GXBEGIN(474, "GXSetZCompLoc");

    gxData = __GXData;
    gxData->peCtrl = (gxData->peCtrl & 0xFFFFFFBF) | ((u32)(u8)before_tex << 6);
    GX_WRITE_RAS_REG(gxData->peCtrl);
    gxData->bpSentNot = 0;
}

void GXSetPixelFmt(GXPixelFmt pix_fmt, GXZFmt16 z_fmt) {
    u32 oldPeCtrl;
    u8 aa;
    static u32 p2f[8] = { 0, 1, 2, 3, 4, 4, 4, 5 };

    CHECK_GXBEGIN(511, "GXSetPixelFmt");
    oldPeCtrl = __GXData->peCtrl;
    ASSERTMSGLINE(515, pix_fmt >= GX_PF_RGB8_Z24 && pix_fmt <= GX_PF_YUV420, "Invalid Pixel format");
    __GXData->peCtrl = (__GXData->peCtrl & ~0x7) | p2f[pix_fmt];
    __GXData->peCtrl = (__GXData->peCtrl & ~0x38) | ((u32)z_fmt << 3);

    if (oldPeCtrl != __GXData->peCtrl) {
        GX_WRITE_RAS_REG(__GXData->peCtrl);
        if (pix_fmt == GX_PF_RGB565_Z16) {
            aa = 1;
        } else {
            aa = 0;
        }
        __GXData->genMode = (__GXData->genMode & ~0x200) | ((u32)aa << 9);
        __GXData->dirtyState |= 4;
    }

    if (p2f[pix_fmt] == 4) {
        u32 reg = __GXData->cmode1;
        reg = (reg & ~0x600) | (((pix_fmt - GX_PF_Y8) & 0x3) << 9);
        __GXData->cmode1 = reg;
        __GXData->cmode1 = (__GXData->cmode1 & ~0xFF000000) | 0x42000000;
        GX_WRITE_RAS_REG(__GXData->cmode1);
    }

    __GXData->bpSentNot = 0;
}

void GXSetDither(GXBool dither) {
    u32 reg;
    CHECK_GXBEGIN(556, "GXSetDither");

    reg = __GXData->cmode0;

    SOME_SET_REG_MACRO(reg, 1, 2, dither);
    GX_WRITE_RAS_REG(reg);

    __GXData->cmode0 = reg;
    __GXData->bpSentNot = 0;
}

void GXSetDstAlpha(GXBool enable, u8 alpha) {
    u32 reg;
    CHECK_GXBEGIN(581, "GXSetDstAlpha");

    reg = __GXData->cmode1;

    SOME_SET_REG_MACRO(reg, 8, 0, alpha);
    SOME_SET_REG_MACRO(reg, 1, 8, enable);
    GX_WRITE_RAS_REG(reg);

    __GXData->cmode1 = reg;
    __GXData->bpSentNot = 0;
}

void GXSetFieldMask(GXBool odd_mask, GXBool even_mask) {
    u32 reg;

    CHECK_GXBEGIN(608, "GXSetFieldMask");

    reg = (u32)(u8)even_mask;
    reg = (reg & ~2) | ((u32)(u8)odd_mask << 1);
    reg = (reg & 0x00FFFFFF) | 0x44000000;
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

void GXSetFieldMode(GXBool field_mode, GXBool half_aspect_ratio) {
    GXData* gxData;
    u32 reg;

    CHECK_GXBEGIN(637, "GXSetFieldMode");
    gxData = __GXData;
    gxData->lpSize = (gxData->lpSize & ~0x00400000) | ((u32)(u8)half_aspect_ratio << 22);
    GX_WRITE_RAS_REG(gxData->lpSize);
    __GXFlushTextureState();
    reg = (u32)(u8)field_mode | 0x68000000;
    GX_WRITE_RAS_REG(reg);
    __GXFlushTextureState();
}
