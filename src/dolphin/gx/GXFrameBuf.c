#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

extern GXData* gx;
#define __GXData gx

extern const f32 GX_F32_256;

static inline u32 __GXGetNumXfbLines(u32 efbHt, u32 iScale) {
    u32 count;
    u32 realHt;
    u32 iScaleD;

    count = (efbHt - 1) * 0x100;
    realHt = (count / iScale) + 1;
    iScaleD = iScale;

    if (iScaleD > 0x80 && iScaleD < 0x100) {
        while ((iScaleD & 1) == 0) {
            iScaleD >>= 1;
        }

        if ((efbHt % iScaleD) == 0) {
            realHt++;
        }
    }

    if (realHt > 0x400) {
        realHt = 0x400;
    }

    return realHt;
}

void GXSetDispCopySrc(u16 left, u16 top, u16 wd, u16 ht) {
    CHECK_GXBEGIN(1235, "GXSetDispCopySrc");
    __GXData->cpDispSrc = 0;
    SET_REG_FIELD(1238, __GXData->cpDispSrc, 10, 0, left);
    SET_REG_FIELD(1239, __GXData->cpDispSrc, 10, 10, top);
    SET_REG_FIELD(1239, __GXData->cpDispSrc, 8, 24, 0x49);

    __GXData->cpDispSize = 0;
    SET_REG_FIELD(1243, __GXData->cpDispSize, 10, 0, wd - 1);
    SET_REG_FIELD(1244, __GXData->cpDispSize, 10, 10, ht - 1);
    SET_REG_FIELD(1244, __GXData->cpDispSize, 8, 24, 0x4A);
}

void GXSetTexCopySrc(u16 left, u16 top, u16 wd, u16 ht) {
    CHECK_GXBEGIN(1263, "GXSetTexCopySrc");

    __GXData->cpTexSrc = 0;
    SET_REG_FIELD(1266, __GXData->cpTexSrc, 10, 0, left);
    SET_REG_FIELD(1267, __GXData->cpTexSrc, 10, 10, top);
    SET_REG_FIELD(1267, __GXData->cpTexSrc, 8, 24, 0x49);

    __GXData->cpTexSize = 0;
    SET_REG_FIELD(1271, __GXData->cpTexSize, 10, 0, wd - 1);
    SET_REG_FIELD(1272, __GXData->cpTexSize, 10, 10, ht - 1);
    SET_REG_FIELD(1272, __GXData->cpTexSize, 8, 24, 0x4A);
}

void GXSetDispCopyDst(u16 wd, u16 ht) {
    u16 stride;

    ASSERTMSGLINE(1293, (wd & 0xF) == 0, "GXSetDispCopyDst: Width must be a multiple of 16");
    CHECK_GXBEGIN(1294, "GXSetDispCopyDst");

    stride = (int)wd * 2;
    gx->cpDispStride = 0;
    SET_REG_FIELD(1299, gx->cpDispStride, 10, 0, stride >> 5);
    SET_REG_FIELD(1300, gx->cpDispStride, 8, 24, 0x4D);
}

void GXSetTexCopyDst(u16 wd, u16 ht, GXTexFmt fmt, GXBool mipmap) {
    u32 rowTiles;
    u32 colTiles;
    u32 cmpTiles;
    u32 peTexFmt;
    u32 peTexFmtH;

    CHECK_GXBEGIN(1327, "GXSetTexCopyDst");

    gx->cpTexZ = 0;
    peTexFmt = fmt & 0xF;
    ASSERTMSGLINEV(1358, peTexFmt < 13, "%s: invalid texture format", "GXSetTexCopyDst");

    if (fmt == GX_TF_Z16) {
        peTexFmt = 0xB;
    }

    switch (fmt) {
    case GX_TF_I4:
    case GX_TF_I8:
    case GX_TF_IA4:
    case GX_TF_IA8:
    case GX_CTF_YUVA8:
        SET_REG_FIELD(0, gx->cpTex, 2, 15, 3);
        break;
    default:
        SET_REG_FIELD(0, gx->cpTex, 2, 15, 2);
        break;
    }

    gx->cpTexZ = (fmt & _GX_TF_ZTF) == _GX_TF_ZTF;
    peTexFmtH = (peTexFmt >> 3) & 1;
    !peTexFmt;
    SET_REG_FIELD(0, gx->cpTex, 1, 3, peTexFmtH);
    peTexFmt = peTexFmt & 7;
    __GetImageTileCount(fmt, wd, ht, &rowTiles, &colTiles, &cmpTiles);

    gx->cpTexStride = 0;
    SET_REG_FIELD(0, gx->cpTexStride, 10, 0, rowTiles * cmpTiles);
    SET_REG_FIELD(0, gx->cpTexStride, 8, 24, 0x4D);
    SET_REG_FIELD(0, gx->cpTex, 1, 9, mipmap);
    SET_REG_FIELD(0, gx->cpTex, 3, 4, peTexFmt);
}

void GXSetDispCopyFrame2Field(GXCopyMode mode) {
    CHECK_GXBEGIN(1410, "GXSetDispCopyFrame2Field");
    SET_REG_FIELD(1411, gx->cpDisp, 2, 12, mode);
    SET_REG_FIELD(1411, gx->cpTex, 2, 12, 0);
}

void GXSetCopyClamp(GXFBClamp clamp) {
    u8 clmpB;
    u8 clmpT;

    CHECK_GXBEGIN(1431, "GXSetCopyClamp");

    clmpT = (clamp & GX_CLAMP_TOP) == GX_CLAMP_TOP;
    clmpB = (clamp & GX_CLAMP_BOTTOM) == GX_CLAMP_BOTTOM;

    SET_REG_FIELD(1435, gx->cpDisp, 1, 0, clmpT);
    SET_REG_FIELD(1436, gx->cpDisp, 1, 1, clmpB);

    SET_REG_FIELD(1438, gx->cpTex, 1, 0, clmpT);
    SET_REG_FIELD(1439, gx->cpTex, 1, 1, clmpB);
}

u32 GXSetDispCopyYScale(f32 vscale) {
    u32 iScale;
    GXBool copyYScaleEnable;
    u32 height;
    u32 reg;

    CHECK_GXBEGIN(1557, "GXSetDispCopyYScale");

    ASSERTMSGLINE(1559, vscale >= 1.0f, "GXSetDispCopyYScale: Vertical scale must be >= 1.0");

    iScale = (u32)(GX_F32_256 / vscale) & 0x1FF;
    reg = 0;
    SET_REG_FIELD(1566, reg, 9, 0, iScale);
    SET_REG_FIELD(1566, reg, 8, 24, 0x4E);
    GX_WRITE_RAS_REG(reg);
    copyYScaleEnable = (iScale != 0x100);
    gx->bpSentNot = 0;
    SET_REG_FIELD(1569, gx->cpDisp, 1, 10, copyYScaleEnable);
    height = (u32)GET_REG_FIELD(gx->cpDispSize, 10, 10) + 1;
    return __GXGetNumXfbLines(height, iScale);
}

void GXSetCopyClear(GXColor clear_clr, u32 clear_z) {
    u32 reg;

    CHECK_GXBEGIN(1596, "GXSetCopyClear");
    ASSERTMSGLINE(1598, clear_z <= 0xFFFFFF, "GXSetCopyClear: Z clear value is out of range");

    reg = 0;
    SET_REG_FIELD(1601, reg, 8, 0, clear_clr.r);
    SET_REG_FIELD(1602, reg, 8, 8, clear_clr.a);
    SET_REG_FIELD(1602, reg, 8, 24, 0x4F);
    GX_WRITE_RAS_REG(reg);

    reg = 0;
    SET_REG_FIELD(1607, reg, 8, 0, clear_clr.b);
    SET_REG_FIELD(1608, reg, 8, 8, clear_clr.g);
    SET_REG_FIELD(1608, reg, 8, 24, 0x50);
    GX_WRITE_RAS_REG(reg);

    reg = 0;
    SET_REG_FIELD(1613, reg, 24, 0, clear_z);
    SET_REG_FIELD(1613, reg, 8, 24, 0x51);
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

void GXSetCopyFilter(GXBool aa, const u8 sample_pattern[12][2], GXBool vf, const u8 vfilter[7]) {
    u32 msLoc[4];
    u32 coeff0;
    u32 coeff1;

    CHECK_GXBEGIN(1641, "GXSetCopyFilter");

    if (aa != 0) {
        msLoc[0] = 0;
        SET_REG_FIELD(0, msLoc[0], 4, 0, sample_pattern[0][0]);
        SET_REG_FIELD(0, msLoc[0], 4, 4, sample_pattern[0][1]);
        SET_REG_FIELD(0, msLoc[0], 4, 8, sample_pattern[1][0]);
        SET_REG_FIELD(0, msLoc[0], 4, 12, sample_pattern[1][1]);
        SET_REG_FIELD(0, msLoc[0], 4, 16, sample_pattern[2][0]);
        SET_REG_FIELD(0, msLoc[0], 4, 20, sample_pattern[2][1]);
        SET_REG_FIELD(0, msLoc[0], 8, 24, 1);

        msLoc[1] = 0;
        SET_REG_FIELD(0, msLoc[1], 4, 0, sample_pattern[3][0]);
        SET_REG_FIELD(0, msLoc[1], 4, 4, sample_pattern[3][1]);
        SET_REG_FIELD(0, msLoc[1], 4, 8, sample_pattern[4][0]);
        SET_REG_FIELD(0, msLoc[1], 4, 12, sample_pattern[4][1]);
        SET_REG_FIELD(0, msLoc[1], 4, 16, sample_pattern[5][0]);
        SET_REG_FIELD(0, msLoc[1], 4, 20, sample_pattern[5][1]);
        SET_REG_FIELD(0, msLoc[1], 8, 24, 2);

        msLoc[2] = 0;
        SET_REG_FIELD(0, msLoc[2], 4, 0, sample_pattern[6][0]);
        SET_REG_FIELD(0, msLoc[2], 4, 4, sample_pattern[6][1]);
        SET_REG_FIELD(0, msLoc[2], 4, 8, sample_pattern[7][0]);
        SET_REG_FIELD(0, msLoc[2], 4, 12, sample_pattern[7][1]);
        SET_REG_FIELD(0, msLoc[2], 4, 16, sample_pattern[8][0]);
        SET_REG_FIELD(0, msLoc[2], 4, 20, sample_pattern[8][1]);
        SET_REG_FIELD(0, msLoc[2], 8, 24, 3);

        msLoc[3] = 0;
        SET_REG_FIELD(0, msLoc[3], 4, 0, sample_pattern[9][0]);
        SET_REG_FIELD(0, msLoc[3], 4, 4, sample_pattern[9][1]);
        SET_REG_FIELD(0, msLoc[3], 4, 8, sample_pattern[10][0]);
        SET_REG_FIELD(0, msLoc[3], 4, 12, sample_pattern[10][1]);
        SET_REG_FIELD(0, msLoc[3], 4, 16, sample_pattern[11][0]);
        SET_REG_FIELD(0, msLoc[3], 4, 20, sample_pattern[11][1]);
        SET_REG_FIELD(0, msLoc[3], 8, 24, 4);
    } else {
        msLoc[0] = 0x01666666;
        msLoc[1] = 0x02666666;
        msLoc[2] = 0x03666666;
        msLoc[3] = 0x04666666;
    }

    GX_WRITE_RAS_REG(msLoc[0]);
    GX_WRITE_RAS_REG(msLoc[1]);
    GX_WRITE_RAS_REG(msLoc[2]);
    GX_WRITE_RAS_REG(msLoc[3]);

    coeff0 = 0;
    SET_REG_FIELD(0, coeff0, 8, 24, 0x53);
    coeff1 = 0;
    SET_REG_FIELD(0, coeff1, 8, 24, 0x54);
    if (vf != 0) {
        SET_REG_FIELD(0, coeff0, 6, 0, vfilter[0]);
        SET_REG_FIELD(0, coeff0, 6, 6, vfilter[1]);
        SET_REG_FIELD(0, coeff0, 6, 12, vfilter[2]);
        SET_REG_FIELD(0, coeff0, 6, 18, vfilter[3]);
        SET_REG_FIELD(0, coeff1, 6, 0, vfilter[4]);
        SET_REG_FIELD(0, coeff1, 6, 6, vfilter[5]);
        SET_REG_FIELD(0, coeff1, 6, 12, vfilter[6]);
    } else {
        SET_REG_FIELD(0, coeff0, 6, 0, 0);
        SET_REG_FIELD(0, coeff0, 6, 6, 0);
        SET_REG_FIELD(0, coeff0, 6, 12, 21);
        SET_REG_FIELD(0, coeff0, 6, 18, 22);
        SET_REG_FIELD(0, coeff1, 6, 0, 21);
        SET_REG_FIELD(0, coeff1, 6, 6, 0);
        SET_REG_FIELD(0, coeff1, 6, 12, 0);
    }

    GX_WRITE_RAS_REG(coeff0);
    GX_WRITE_RAS_REG(coeff1);
    __GXData->bpSentNot = 0;
}

void GXSetDispCopyGamma(GXGamma gamma) {
    CHECK_GXBEGIN(1741, "GXSetDispCopyGamma");
    __GXData->cpDisp = (__GXData->cpDisp & 0xFFFFFE7F) | ((u32)gamma << 7);
}

void GXCopyDisp(void* dest, GXBool clear) {
    u32 reg;
    u32 tempPeCtrl;
    u32 phyAddr;
    u8 changePeCtrl;

    CHECK_GXBEGIN(1833, "GXCopyDisp");

    if (clear) {
        reg = __GXData->zmode;
        SET_REG_FIELD(0, reg, 1, 0, 1);
        SET_REG_FIELD(0, reg, 3, 1, 7);
        GX_WRITE_RAS_REG(reg);

        reg = __GXData->cmode0;
        SET_REG_FIELD(0, reg, 1, 0, 0);
        SET_REG_FIELD(0, reg, 1, 1, 0);
        GX_WRITE_RAS_REG(reg);
    }

    changePeCtrl = FALSE;
    if ((clear || (u32)GET_REG_FIELD(__GXData->peCtrl, 3, 0) == 3)
        && (u32)GET_REG_FIELD(__GXData->peCtrl, 1, 6) == 1) {
        changePeCtrl = TRUE;
        tempPeCtrl = __GXData->peCtrl;
        SET_REG_FIELD(0, tempPeCtrl, 1, 6, 0);
        GX_WRITE_RAS_REG(tempPeCtrl);
    }

    GX_WRITE_RAS_REG(__GXData->cpDispSrc);
    GX_WRITE_RAS_REG(__GXData->cpDispSize);
    GX_WRITE_RAS_REG(__GXData->cpDispStride);

    phyAddr = (u32)dest & 0x3FFFFFFF;
    reg = 0;
    SET_REG_FIELD(0, reg, 21, 0, phyAddr >> 5);
    SET_REG_FIELD(0, reg, 8, 24, 0x4B);
    GX_WRITE_RAS_REG(reg);

    SET_REG_FIELD(0, __GXData->cpDisp, 1, 11, clear);
    SET_REG_FIELD(0, __GXData->cpDisp, 1, 14, 1);
    SET_REG_FIELD(0, __GXData->cpDisp, 8, 24, 0x52);
    GX_WRITE_RAS_REG(__GXData->cpDisp);

    if (clear) {
        GX_WRITE_RAS_REG(__GXData->zmode);
        GX_WRITE_RAS_REG(__GXData->cmode0);
    }

    if (changePeCtrl) {
        GX_WRITE_RAS_REG(__GXData->peCtrl);
    }

    __GXData->bpSentNot = 0;
}

void GXCopyTex(void* dest, GXBool clear) {
    u32 reg;
    u32 tempPeCtrl;
    u32 phyAddr;
    u8 changePeCtrl;

    CHECK_GXBEGIN(1916, "GXCopyTex");

    if (clear != 0) {
        reg = __GXData->zmode;
        SET_REG_FIELD(0, reg, 1, 0, 1);
        SET_REG_FIELD(0, reg, 3, 1, 7);
        GX_WRITE_RAS_REG(reg);

        reg = __GXData->cmode0;
        SET_REG_FIELD(0, reg, 1, 0, 0);
        SET_REG_FIELD(0, reg, 1, 1, 0);
        GX_WRITE_RAS_REG(reg);
    }

    changePeCtrl = 0;
    tempPeCtrl = __GXData->peCtrl;

    if (((u8)__GXData->cpTexZ != 0) && ((u32)(tempPeCtrl & 7) != 3)) {
        changePeCtrl = 1;
        tempPeCtrl = (tempPeCtrl & 0xFFFFFFF8) | 3;
    }

    if (((clear != 0) || ((u32)(tempPeCtrl & 7) == 3)) && ((u32)((tempPeCtrl >> 6U) & 1) == 1)) {
        changePeCtrl = 1;
        tempPeCtrl &= 0xFFFFFFBF;
    }

    if (changePeCtrl) {
        GX_WRITE_RAS_REG(tempPeCtrl);
    }

    GX_WRITE_RAS_REG(__GXData->cpTexSrc);
    GX_WRITE_RAS_REG(__GXData->cpTexSize);
    GX_WRITE_RAS_REG(__GXData->cpTexStride);

    phyAddr = (u32)dest & 0x3FFFFFFF;
    reg = 0;
    SET_REG_FIELD(0, reg, 21, 0, phyAddr >> 5);
    SET_REG_FIELD(0, reg, 8, 24, 0x4B);
    GX_WRITE_RAS_REG(reg);

    SET_REG_FIELD(0, __GXData->cpTex, 1, 11, clear);
    SET_REG_FIELD(0, __GXData->cpTex, 1, 14, 0);
    SET_REG_FIELD(0, __GXData->cpTex, 8, 24, 0x52);
    GX_WRITE_RAS_REG(__GXData->cpTex);

    if (clear != 0) {
        GX_WRITE_RAS_REG(__GXData->zmode);
        GX_WRITE_RAS_REG(__GXData->cmode0);
    }

    if (changePeCtrl) {
        GX_WRITE_RAS_REG(__GXData->peCtrl);
    }

    __GXData->bpSentNot = 0;
}

void GXClearBoundingBox(void) {
    u32 reg;

    CHECK_GXBEGIN(2003, "GXClearBoundingBox");
    reg = 0x550003FF;
    GX_WRITE_RAS_REG(reg);
    reg = 0x560003FF;
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}
