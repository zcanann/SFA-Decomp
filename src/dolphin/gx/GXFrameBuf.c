#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

GXRenderModeObj GXNtsc480IntDf = {
    0, 640, 480, 480, 40, 0, 640, 480, 1, 0, 0, { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 }, { 8, 8, 10, 12, 10, 8, 8 }
};

GXRenderModeObj GXMpal480IntDf = {8, 640, 480, 480, 40, 0, 640, 480, 1, 0, 0, { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 }, { 8, 8, 10, 12, 10, 8, 8 } };
GXRenderModeObj GXPal528IntDf = {4, 640, 528, 528, 40, 23, 640, 528, 1, 0, 0, { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 }, { 8, 8, 10, 12, 10, 8, 8 } };
GXRenderModeObj GXEurgb60Hz480IntDf = {20, 640, 480, 480, 40, 0, 640, 480, 1, 0, 0, { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 }, { 8, 8, 10, 12, 10, 8, 8 } };

void GXAdjustForOverscan(const GXRenderModeObj* rmin, GXRenderModeObj* rmout, u16 hor, u16 ver) {
    u16 hor2 = hor * 2;
    u16 ver2 = ver * 2;
    u32 verf;

    if (rmin != rmout) {
        *rmout = *rmin;
    }

    rmout->fbWidth = rmin->fbWidth - hor2;
    verf = (ver2 * rmin->efbHeight) / (u32)rmin->xfbHeight;
    rmout->efbHeight = rmin->efbHeight - verf;
    if (rmin->xFBmode == VI_XFBMODE_SF && (rmin->viTVmode & 2) != 2) {
        rmout->xfbHeight = rmin->xfbHeight - ver;
    } else {
        rmout->xfbHeight = rmin->xfbHeight - ver2;
    }

    rmout->viWidth = rmin->viWidth - hor2;
    rmout->viHeight = rmin->viHeight - ver2;
 
    rmout->viXOrigin = rmin->viXOrigin + hor;
    rmout->viYOrigin = rmin->viYOrigin + ver;
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

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXSetDispCopyDst(u16 wd, u16 ht) {
    ASSERTMSGLINE(1293, (wd & 0xF) == 0, "GXSetDispCopyDst: Width must be a multiple of 16");
    CHECK_GXBEGIN(1294, "GXSetDispCopyDst");
    __GXData->cpDispStride = 0;
    __GXData->cpDispStride = (__GXData->cpDispStride & 0xFFFFFC00) | ((int)((wd & 0x7FFF) << 1) >> 5);
    __GXData->cpDispStride = (__GXData->cpDispStride & 0x00FFFFFF) | 0x4D000000;
}

void GXSetTexCopyDst(u16 wd, u16 ht, GXTexFmt fmt, GXBool mipmap) {
    u32 rowTiles;
    u32 colTiles;
    u32 cmpTiles;
    u32 peTexFmt;
    u32 peTexFmtH;

    CHECK_GXBEGIN(1327, "GXSetTexCopyDst");

    __GXData->cpTexZ = 0;
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
        __GXData->cpTex = (__GXData->cpTex & 0xFFFE7FFF) | 0x18000;
        break;
    default:
        __GXData->cpTex = (__GXData->cpTex & 0xFFFE7FFF) | 0x10000;
        break;
    }

    __GXData->cpTexZ = (fmt & _GX_TF_ZTF) == _GX_TF_ZTF;
    peTexFmtH = (peTexFmt >> 3) & 1;
    !peTexFmt;
    SET_REG_FIELD(0, __GXData->cpTex, 1, 3, peTexFmtH);
    peTexFmt = peTexFmt & 7;
    __GetImageTileCount(fmt, wd, ht, &rowTiles, &colTiles, &cmpTiles);

    __GXData->cpTexStride = 0;
    SET_REG_FIELD(0, __GXData->cpTexStride, 10, 0, rowTiles * cmpTiles);
    SET_REG_FIELD(0, __GXData->cpTexStride, 8, 24, 0x4D);
    SET_REG_FIELD(0, __GXData->cpTex, 1, 9, mipmap);
    SET_REG_FIELD(0, __GXData->cpTex, 3, 4, peTexFmt);
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
void GXSetDispCopyFrame2Field(GXCopyMode mode) {
    GXData* gxData;
    u32* cpTex;
    u32 reg;

    CHECK_GXBEGIN(1410, "GXSetDispCopyFrame2Field");
    gxData = __GXData;

    reg = gxData->cpDisp;
    reg = (reg & 0xFFFFCFFF) | ((u32)mode << 12);
    gxData->cpDisp = reg;

    cpTex = &gxData->cpTex;
    reg = *cpTex;
    reg &= 0xFFFFCFFF;
    *cpTex = reg;
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
void GXSetCopyClamp(GXFBClamp clamp) {
    u32 reg;
    u32 clmpB;
    GXData* gxData;

    CHECK_GXBEGIN(1431, "GXSetCopyClamp");
    gxData = __GXData;

    reg = gxData->cpDisp;
    reg = (reg & 0xFFFFFFFE) | ((((u32)__cntlzw((clamp & GX_CLAMP_TOP) - GX_CLAMP_TOP)) >> 5) & 0xFF);
    gxData->cpDisp = reg;

    clmpB = ((u32)__cntlzw((clamp & GX_CLAMP_BOTTOM) - GX_CLAMP_BOTTOM) >> 4) & 0x1FE;
    reg = gxData->cpDisp;
    reg &= 0xFFFFFFFD;
    gxData->cpDisp = reg | clmpB;

    reg = gxData->cpTex;
    reg = (reg & 0xFFFFFFFE) | ((((u32)__cntlzw((clamp & GX_CLAMP_TOP) - GX_CLAMP_TOP)) >> 5) & 0xFF);
    gxData->cpTex = reg;

    reg = gxData->cpTex;
    reg = (reg & 0xFFFFFFFD) | clmpB;
    gxData->cpTex = reg;
}

static inline u32 __GXGetNumXfbLines(u32 efbHt, u32 iScale) {
    u32 count;
    u32 realHt;
    u32 iScaleD;

    count = (efbHt - 1) * 0x100;
    realHt = (count / iScale) + 1;

    iScaleD = iScale;

    if (iScaleD > 0x80 && iScaleD < 0x100) {
        while (iScaleD % 2 == 0) {
            iScaleD /= 2;
        }

        if (efbHt % iScaleD == 0) {
            realHt++;
        }
    }

    if (realHt > 0x400) {
        realHt = 0x400;
    }

    return realHt;
}

f32 GXGetYScaleFactor(u16 efbHeight, u16 xfbHeight) {
    f32 fScale;
    f32 yScale;
    u32 iScale;
    u32 tgtHt;
    u32 realHt;

    ASSERTMSGLINE(1510, xfbHeight <= 1024, "GXGetYScaleFactor: Display copy only supports up to 1024 lines.\n");
    ASSERTMSGLINE(1512, efbHeight <= xfbHeight, "GXGetYScaleFactor: EFB height should not be greater than XFB height.\n");

    tgtHt = xfbHeight;
    yScale = (f32)xfbHeight / (f32)efbHeight;
    iScale = (u32)(256.0f / yScale) & 0x1FF;
    realHt = __GXGetNumXfbLines(efbHeight, iScale);

    while (realHt > xfbHeight) {
        tgtHt--;
        yScale = (f32)tgtHt / (f32)efbHeight;
        iScale = (u32)(256.0f / yScale) & 0x1FF;
        realHt = __GXGetNumXfbLines(efbHeight, iScale);
    }

    fScale = yScale;
    while (realHt < xfbHeight) {
        fScale = yScale;
        tgtHt++;
        yScale = (f32)tgtHt / (f32)efbHeight;
        iScale = (u32)(256.0f / yScale) & 0x1FF;
        realHt = __GXGetNumXfbLines(efbHeight, iScale);
    }

    return fScale;
}

u32 GXSetDispCopyYScale(f32 vscale) {
    u32 iScale;
    GXBool copyYScaleEnable;

    CHECK_GXBEGIN(1557, "GXSetDispCopyYScale");

    ASSERTMSGLINE(1559, vscale >= 1.0f, "GXSetDispCopyYScale: Vertical scale must be >= 1.0");

    iScale = (u32)(256.0f / vscale) & 0x1FF;
    GX_WRITE_RAS_REG((iScale & 0x1FF) | 0x4E000000);
    copyYScaleEnable = (iScale != 0x100);
    __GXData->bpSentNot = 0;
    __GXData->cpDisp = (__GXData->cpDisp & ~0x400) | ((u32)copyYScaleEnable << 10);
    return __GXGetNumXfbLines((((u32)__GXData->cpDispSize >> 10) & 0x3FF) + 1, iScale);
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

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
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

#if DEBUG
static void __GXVerifCopy(void* dest, u8 clear) {
    u8 clmpT;
    u8 clmpB;
    u32 x0;
    u32 y0;
    u32 dx;
    u32 dy;

    CHECK_GXBEGIN(1762, "GXCopyDisp");

    clmpT = GET_REG_FIELD(__GXData->cpDisp, 1, 0);
    clmpB = (u32)GET_REG_FIELD(__GXData->cpDisp, 1, 1);
    x0 = GET_REG_FIELD(__GXData->cpDispSrc, 10, 0);
    dx = GET_REG_FIELD(__GXData->cpDispSize, 10, 0) + 1;
    y0 = GET_REG_FIELD(__GXData->cpDispSrc, 10, 10);
    dy = GET_REG_FIELD(__GXData->cpDispSize, 10, 10) + 1;

    ASSERTMSGLINE(1772, clmpT || y0 != 0, "GXCopy: Have to set GX_CLAMP_TOP if source top == 0");
    ASSERTMSGLINE(1774, clmpB || y0 + dy <= 528, "GXCopy: Have to set GX_CLAMP_BOTTOM if source bottom > 528");
    ASSERTMSGLINE(1779, (__GXData->peCtrl & 7) != 3 || clear == 0, "GXCopy: Can not do clear while pixel type is Z");
    
    if ((u32) (__GXData->peCtrl & 7) == 5) {
        ASSERTMSGLINE(1785, clear == 0, "GXCopy: Can not clear YUV framebuffer");
        ASSERTMSGLINE(1787, (x0 & 3) == 0, "GXCopy: Source x is not multiple of 4 for YUV copy");
        ASSERTMSGLINE(1789, (y0 & 3) == 0, "GXCopy: Source y is not multiple of 4 for YUV copy");
        ASSERTMSGLINE(1791, (dx & 3) == 0, "GXCopy: Source width is not multiple of 4 for YUV copy");
        ASSERTMSGLINE(1793, (dy & 3) == 0, "GXCopy: Source height is not multiple of 4 for YUV copy");
    } else {
        ASSERTMSGLINE(1797, (x0 & 1) == 0, "GXCopy: Source x is not multiple of 2 for RGB copy");
        ASSERTMSGLINE(1799, (y0 & 1) == 0, "GXCopy: Source y is not multiple of 2 for RGB copy");
        ASSERTMSGLINE(1801, (dx & 1) == 0, "GXCopy: Source width is not multiple of 2 for RGB copy");
        ASSERTMSGLINE(1803, (dy & 1) == 0, "GXCopy: Source height is not multiple of 2 for RGB copy");
    }

    ASSERTMSGLINE(1807, ((u32)dest & 0x1F) == 0, "GXCopy: Display destination address not 32B aligned");
}
#endif

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXCopyDisp(void* dest, GXBool clear) {
    u32 reg;
    u32 tempPeCtrl;
    u32 phyAddr;
    u8 changePeCtrl;

    CHECK_GXBEGIN(1833, "GXCopyDisp");

#if DEBUG
    __GXVerifCopy(dest, clear);
#endif

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
    if ((clear || (u32)GET_REG_FIELD(__GXData->peCtrl, 3, 0) == 3) && (u32)GET_REG_FIELD(__GXData->peCtrl, 1, 6) == 1) {
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

#if DEBUG
    __GXVerifCopy(dest, clear);
#endif
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
