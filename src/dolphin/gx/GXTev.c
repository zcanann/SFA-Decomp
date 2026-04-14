#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

static struct {
    u32 rid : 8;
    u32 dest : 2;
    u32 shift : 2;
    u32 clamp : 1;
    u32 sub : 1;
    u32 bias : 2;
    u32 sela : 4;
    u32 selb : 4;
    u32 selc : 4;
    u32 seld : 4;
} TEVCOpTableST0[5] = {
    {192, 0, 0, 1, 0, 0, 15, 8, 10, 15},   // modulate
    {192, 0, 0, 1, 0, 0, 10, 8, 9, 15},    // decal
    {192, 0, 0, 1, 0, 0, 10, 12, 8, 15},   // blend
    {192, 0, 0, 1, 0, 0, 15, 15, 15, 8},   // replace
    {192, 0, 0, 1, 0, 0, 15, 15, 15, 10},  // passclr
};

static struct {
    u32 rid : 8;
    u32 dest : 2;
    u32 shift : 2;
    u32 clamp : 1;
    u32 sub : 1;
    u32 bias : 2;
    u32 sela : 4;
    u32 selb : 4;
    u32 selc : 4;
    u32 seld : 4;
} TEVCOpTableST1[5] = {
    {192, 0, 0, 1, 0, 0, 15, 8, 0, 15},   // modulate
    {192, 0, 0, 1, 0, 0, 0, 8, 9, 15},    // decal
    {192, 0, 0, 1, 0, 0, 0, 12, 8, 15},   // blend
    {192, 0, 0, 1, 0, 0, 15, 15, 15, 8},  // replace
    {192, 0, 0, 1, 0, 0, 15, 15, 15, 0},  // passclr
};

static struct {
    u32 rid : 8;
    u32 dest : 2;
    u32 shift : 2;
    u32 clamp : 1;
    u32 sub : 1;
    u32 bias : 2;
    u32 sela : 3;
    u32 selb : 3;
    u32 selc : 3;
    u32 seld : 3;
    u32 swap : 2;
    u32 mode : 2;
} TEVAOpTableST0[5] = {
    {193, 0, 0, 1, 0, 0, 7, 4, 5, 7, 0, 0},  // modulate
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 5, 0, 0},  // decal
    {193, 0, 0, 1, 0, 0, 7, 4, 5, 7, 0, 0},  // blend
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 4, 0, 0},  // replace
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 5, 0, 0},  // passclr
};

static struct {
    u32 rid : 8;
    u32 dest : 2;
    u32 shift : 2;
    u32 clamp : 1;
    u32 sub : 1;
    u32 bias : 2;
    u32 sela : 3;
    u32 selb : 3;
    u32 selc : 3;
    u32 seld : 3;
    u32 swap : 2;
    u32 mode : 2;
} TEVAOpTableST1[5] = {
    {193, 0, 0, 1, 0, 0, 7, 4, 0, 7, 0, 0},  // modulate
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 0, 0, 0},  // decal
    {193, 0, 0, 1, 0, 0, 7, 4, 0, 7, 0, 0},  // blend
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 4, 0, 0},  // replace
    {193, 0, 0, 1, 0, 0, 7, 7, 7, 0, 0, 0},  // passclr
};

#define SOME_SET_REG_MACRO(reg, size, shift, val)                                                   \
	do {                                                                                            \
		(reg) = (u32)__rlwimi((u32)(reg), (val), (shift), (32 - (shift) - (size)), (31 - (shift))); \
	} while (0);

void GXSetTevOp(GXTevStageID id, GXTevMode mode) {
    u32* ctmp;
    u32* atmp;
    u32 tevReg;

    CHECK_GXBEGIN(420, "GXSetTevOp");
    ASSERTMSGLINE(421, id < GX_MAX_TEVSTAGE, "GXSetTevColor*: Invalid Tev Stage Index");
    ASSERTMSGLINE(422, mode <= GX_PASSCLR, "GXSetTevOp: Invalid Tev Mode");

    if (id == GX_TEVSTAGE0) {
        ctmp = (u32*)TEVCOpTableST0 + mode;
        atmp = (u32*)TEVAOpTableST0 + mode;
    } else {
        ctmp = (u32*)TEVCOpTableST1 + mode;
        atmp = (u32*)TEVAOpTableST1 + mode;
    }

    tevReg = __GXData->tevc[id];
    tevReg = (*ctmp & ~0xFF000000) | (tevReg & 0xFF000000);
    GX_WRITE_RAS_REG(tevReg);
    __GXData->tevc[id] = tevReg;

    tevReg = __GXData->teva[id];
    tevReg = (*atmp & ~0xFF00000F) | (tevReg & 0xFF00000F);
    GX_WRITE_RAS_REG(tevReg);
    __GXData->teva[id] = tevReg;

    __GXData->bpSentNot = 0;
}

void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d) {
    u32 tevReg;

    CHECK_GXBEGIN(578, "GXSetTevColorIn");
    ASSERTMSGLINE(579, stage < GX_MAX_TEVSTAGE, "GXSetTevColor*: Invalid Tev Stage Index");
    ASSERTMSGLINE(580, a <= GX_CC_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(581, b <= GX_CC_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(582, c <= GX_CC_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(583, d <= GX_CC_ZERO, "GXSetTev*In: A/B/C/D argument out of range");

    tevReg = __GXData->tevc[stage];
    SOME_SET_REG_MACRO(tevReg, 4, 12, a);
    SOME_SET_REG_MACRO(tevReg, 4,  8, b);
    SOME_SET_REG_MACRO(tevReg, 4,  4, c);
    SOME_SET_REG_MACRO(tevReg, 4,  0, d);

    GX_WRITE_RAS_REG(tevReg);
    __GXData->tevc[stage] = tevReg;
    __GXData->bpSentNot = 0;
}

void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d) {
    u32 tevReg;

    CHECK_GXBEGIN(614, "GXSetTevAlphaIn");
    ASSERTMSGLINE(615, stage < GX_MAX_TEVSTAGE, "GXSetTevAlpha*: Invalid Tev Stage Index");
    ASSERTMSGLINE(616, a <= GX_CA_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(617, b <= GX_CA_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(618, c <= GX_CA_ZERO, "GXSetTev*In: A/B/C/D argument out of range");
    ASSERTMSGLINE(619, d <= GX_CA_ZERO, "GXSetTev*In: A/B/C/D argument out of range");

    tevReg = __GXData->teva[stage];
    SOME_SET_REG_MACRO(tevReg, 3, 13, a);
    SOME_SET_REG_MACRO(tevReg, 3, 10, b);
    SOME_SET_REG_MACRO(tevReg, 3,  7, c);
    SOME_SET_REG_MACRO(tevReg, 3,  4, d);

    GX_WRITE_RAS_REG(tevReg);
    __GXData->teva[stage] = tevReg;
    __GXData->bpSentNot = 0;
}

void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg) {
    u32 tevReg;

    CHECK_GXBEGIN(653, "GXSetTevColorOp");
    ASSERTMSGLINE(654, stage < GX_MAX_TEVSTAGE, "GXSetTevColor*: Invalid Tev Stage Index");

    tevReg = __GXData->tevc[stage];
    SOME_SET_REG_MACRO(tevReg, 1, 18, op & 1);
    if (op <= 1) {
        SOME_SET_REG_MACRO(tevReg, 2, 20, scale);
        SOME_SET_REG_MACRO(tevReg, 2, 16, bias);
    } else {
        SOME_SET_REG_MACRO(tevReg, 2, 20, (op >> 1) & 3);
        SOME_SET_REG_MACRO(tevReg, 2, 16, 3);
    }
    SOME_SET_REG_MACRO(tevReg, 1, 19, clamp & 0xFF);
    SOME_SET_REG_MACRO(tevReg, 2, 22, out_reg);

    GX_WRITE_RAS_REG(tevReg);
    __GXData->tevc[stage] = tevReg;
    __GXData->bpSentNot = 0;
}

void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg) {
    u32 tevReg;

    CHECK_GXBEGIN(699, "GXSetTevAlphaOp");
    ASSERTMSGLINE(700, stage < GX_MAX_TEVSTAGE, "GXSetTevAlpha*: Invalid Tev Stage Index");

    tevReg = __GXData->teva[stage];
    SOME_SET_REG_MACRO(tevReg, 1, 18, op & 1);
    if (op <= 1) {
        SOME_SET_REG_MACRO(tevReg, 2, 20, scale);
        SOME_SET_REG_MACRO(tevReg, 2, 16, bias);
    } else {
        SOME_SET_REG_MACRO(tevReg, 2, 20, (op >> 1) & 3);
        SOME_SET_REG_MACRO(tevReg, 2, 16, 3);
    }
    SOME_SET_REG_MACRO(tevReg, 1, 19, clamp & 0xFF);
    SOME_SET_REG_MACRO(tevReg, 2, 22, out_reg);

    GX_WRITE_RAS_REG(tevReg);
    __GXData->teva[stage] = tevReg;
    __GXData->bpSentNot = 0;
}

void GXSetTevColor(GXTevRegID id, GXColor color) {
    u8 a;
    u8 r;
    u8 g;
    u8 b;
    u32 regRA;
    u32 regBG;

    CHECK_GXBEGIN(740, "GXSetTevColor");
    a = color.a;
    r = color.r;
    regRA = r;
    regRA = (regRA & ~0x000FF000) | ((u32)a << 12);
    g = color.g;
    b = color.b;
    regRA = (regRA & ~0xFF000000) | (((id * 2) + 0xE0) << 24);
    regBG = b;
    regBG = (regBG & ~0x000FF000) | ((u32)g << 12);
    regBG = (regBG & ~0xFF000000) | (((id * 2) + 0xE1) << 24);

    GX_WRITE_RAS_REG(regRA);
    GX_WRITE_RAS_REG(regBG);
    GX_WRITE_RAS_REG(regBG);
    GX_WRITE_RAS_REG(regBG);

    __GXData->bpSentNot = 0;
}

void GXSetTevColorS10(GXTevRegID id, GXColorS10 color) {
    s16 r;
    s16 g;
    s16 b;
    s16 a;
    u32 regRA;
    u32 regBG;

    ASSERTMSGLINE(777, color.r >= -1024 && color.r < 1024, "GXSetTevColorS10: Color not in range -1024 to +1023");
    ASSERTMSGLINE(778, color.g >= -1024 && color.g < 1024, "GXSetTevColorS10: Color not in range -1024 to +1023");
    ASSERTMSGLINE(779, color.b >= -1024 && color.b < 1024, "GXSetTevColorS10: Color not in range -1024 to +1023");
    ASSERTMSGLINE(780, color.a >= -1024 && color.a < 1024, "GXSetTevColorS10: Color not in range -1024 to +1023");

    CHECK_GXBEGIN(782, "GXSetTevColorS10");
    r = color.r;
    a = color.a;
    b = color.b;
    g = color.g;
    regRA = r & 0x7FF;
    regRA = (regRA & ~0x7FF000) | ((u32)(a & 0x7FF) << 12);
    regRA = (regRA & ~0xFF000000) | (((id * 2) + 0xE0) << 24);

    regBG = b & 0x7FF;
    regBG = (regBG & ~0x7FF000) | ((u32)(g & 0x7FF) << 12);
    regBG = (regBG & ~0xFF000000) | (((id * 2) + 0xE1) << 24);

    GX_WRITE_RAS_REG(regRA);
    GX_WRITE_RAS_REG(regBG);
    GX_WRITE_RAS_REG(regBG);
    GX_WRITE_RAS_REG(regBG);

    __GXData->bpSentNot = 0;
}

void GXSetTevKColor(GXTevKColorID id, GXColor color) {
    u8 a;
    u8 r;
    u8 g;
    u8 b;
    u32 id2;
    u32 regRA;
    u32 regBG;

    CHECK_GXBEGIN(833, "GXSetTevKColor");
    id2 = id * 2;
    r = color.r;
    regRA = r;
    a = color.a;
    regRA = (regRA & ~0x000FF000) | ((u32)a << 12);
    regRA = (regRA & ~0x00F00000) | (8 << 20);
    regRA = (regRA & ~0xFF000000) | ((id2 + 0xE0) << 24);

    b = color.b;
    regBG = b;
    g = color.g;
    regBG = (regBG & ~0x000FF000) | ((u32)g << 12);
    regBG = (regBG & ~0x00F00000) | (8 << 20);
    regBG = (regBG & ~0xFF000000) | ((id2 + 0xE1) << 24);

    GX_WRITE_RAS_REG(regRA);
    GX_WRITE_RAS_REG(regBG);

    __GXData->bpSentNot = 0;
}

void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel) {
    u32* Kreg;

    CHECK_GXBEGIN(872, "GXSetTevKColorSel");
    ASSERTMSGLINE(873, stage < GX_MAX_TEVSTAGE, "GXSetTevKColor*: Invalid Tev Stage Index");

    Kreg = &__GXData->tevKsel[stage >> 1];
    if (stage & 1) {
        *Kreg = (*Kreg & 0xFFF83FFF) | ((u32)sel << 14);
    } else {
        *Kreg = (*Kreg & 0xFFFFFE0F) | ((u32)sel << 4);
    }

    GX_WRITE_RAS_REG(*Kreg);
    __GXData->bpSentNot = 0;
}

void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel) {
    u32* Kreg;

    CHECK_GXBEGIN(905, "GXSetTevKAlphaSel");
    ASSERTMSGLINE(906, stage < GX_MAX_TEVSTAGE, "GXSetTevKColor*: Invalid Tev Stage Index");

    Kreg = &__GXData->tevKsel[stage >> 1];
    if (stage & 1) {
        *Kreg = (*Kreg & 0xFF07FFFF) | ((u32)sel << 19);
    } else {
        *Kreg = (*Kreg & 0xFFFFC1FF) | ((u32)sel << 9);
    }

    GX_WRITE_RAS_REG(*Kreg);
    __GXData->bpSentNot = 0;
}

void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel) {
    u32* pTevReg;

    CHECK_GXBEGIN(942, "GXSetTevSwapMode");
    ASSERTMSGLINE(943, stage < GX_MAX_TEVSTAGE, "GXSetTevSwapMode: Invalid Tev Stage Index");

    pTevReg = &__GXData->teva[stage];
    *pTevReg = (*pTevReg & 0xFFFFFFFC) | ras_sel;
    *pTevReg = (*pTevReg & 0xFFFFFFF3) | ((u32)tex_sel << 2);

    GX_WRITE_RAS_REG(*pTevReg);
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
void GXSetTevSwapModeTable(GXTevSwapSel table, GXTevColorChan red, GXTevColorChan green, GXTevColorChan blue, GXTevColorChan alpha) {
    u32* reg1;
    u32* reg0;
    u32 idx;

    CHECK_GXBEGIN(978, "GXSetTevSwapModeTable");
    ASSERTMSGLINE(979, table < GX_MAX_TEVSWAP, "GXSetTevSwapModeTable: Invalid Swap Selection Index");

    idx = table * 2;
    reg0 = &__GXData->tevKsel[idx];
    *reg0 = (*reg0 & 0xFFFFFFFC) | (u32)red;
    *reg0 = (*reg0 & 0xFFFFFFF3) | ((u32)green << 2);

    GX_WRITE_RAS_REG(*reg0);

    reg1 = &__GXData->tevKsel[idx + 1];
    *reg1 = (*reg1 & 0xFFFFFFFC) | (u32)blue;
    *reg1 = (*reg1 & 0xFFFFFFF3) | ((u32)alpha << 2);

    GX_WRITE_RAS_REG(*reg1);
    __GXData->bpSentNot = 0;
}

void GXSetTevClampMode(void) {
    ASSERTMSGLINE(1012, 0, "GXSetTevClampMode: not available on this hardware");
}

void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1) {
    u32 reg;

    CHECK_GXBEGIN(1046, "GXSetAlphaCompare");
    reg = (ref0 & 0xFF) | 0xF3000000;
    reg = (reg & 0xFFFF00FF) | ((ref1 & 0xFF) << 8);
    reg = (reg & 0xFFF8FFFF) | ((u32)comp0 << 16);
    reg = (reg & 0xFFC7FFFF) | ((u32)comp1 << 19);
    reg = (reg & 0xFF3FFFFF) | ((u32)op << 22);

    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

void GXSetZTexture(GXZTexOp op, GXTexFmt fmt, u32 bias) {
    u32 zenv0;
    u32 zenv1;
    u32 type;

    CHECK_GXBEGIN(1077, "GXSetZTexture");

    zenv0 = bias & 0x00FFFFFF;
    zenv0 = (zenv0 & ~0xFF000000) | (0xF4 << 24);

    zenv1 = 0;
    switch (fmt) {
    case GX_TF_Z8:
        type = 0;
        break;
    case GX_TF_Z16:
        type = 1;
        break;
    case GX_TF_Z24X8:
        type = 2;
        break;
    default:
        ASSERTMSGLINE(1089, 0, "GXSetZTexture: Invalid z-texture format");
        type = 2;
        break;
    }

    zenv1 = 0;
    zenv1 = (zenv1 & ~0x00000003) | type;
    zenv1 = (zenv1 & ~0x0000000C) | ((u32)op << 2);
    zenv1 = (zenv1 & ~0xFF000000) | (0xF5 << 24);

    GX_WRITE_RAS_REG(zenv0);
    GX_WRITE_RAS_REG(zenv1);
    __GXData->bpSentNot = 0;
}

void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color) {
    u32* ptref;
    u32 tmap;
    u32 tcoord;
    static int c2r[10] = { 0, 1, 0, 1, 0, 1, 7, 5, 6, 0 };

    CHECK_GXBEGIN(1131, "GXSetTevOrder");
    ASSERTMSGLINE(1132, stage < GX_MAX_TEVSTAGE, "GXSetTevOrder: Invalid Tev Stage Index");
    ASSERTMSGLINE(1134, coord < GX_MAX_TEXCOORD || coord == GX_TEXCOORD_NULL, "GXSetTevOrder: Invalid Texcoord");
    ASSERTMSGLINE(1136, (map & ~GX_TEX_DISABLE) < GX_MAX_TEXMAP || map == GX_TEXMAP_NULL, "GXSetTevOrder: Invalid Tex Map");
    ASSERTMSGLINE(1138, color >= GX_COLOR0A0 && color <= GX_COLOR_NULL, "GXSetTevOrder: Invalid Color Channel ID");

    ptref = &__GXData->tref[stage / 2];
    __GXData->texmapId[stage] = map;

    tmap = map & ~GX_TEX_DISABLE;
    tmap = (tmap >= GX_MAX_TEXMAP) ? GX_TEXMAP0 : tmap;

    if (coord >= GX_MAX_TEXCOORD) {
        tcoord = GX_TEXCOORD0;
        __GXData->tevTcEnab = __GXData->tevTcEnab & ~(1 << stage);
    } else {
        tcoord = coord;
        __GXData->tevTcEnab = __GXData->tevTcEnab | (1 << stage);
    }

    if (stage & 1) {
        *ptref = (*ptref & 0xFFFF8FFF) | ((u32)tmap << 12);
        *ptref = (*ptref & 0xFFFC7FFF) | ((u32)tcoord << 15);
        *ptref = (*ptref & 0xFFC7FFFF) | ((u32)((color == GX_COLOR_NULL) ? 7 : c2r[color]) << 19);
        *ptref = (*ptref & 0xFFFBFFFF) | ((u32)(map != GX_TEXMAP_NULL && !(map & GX_TEX_DISABLE)) << 18);
    } else {
        *ptref = (*ptref & 0xFFFFFFF8) | (u32)tmap;
        *ptref = (*ptref & 0xFFFFFFC7) | ((u32)tcoord << 3);
        *ptref = (*ptref & 0xFFFFFC7F) | ((u32)((color == GX_COLOR_NULL) ? 7 : c2r[color]) << 7);
        *ptref = (*ptref & 0xFFFFFFBF) | ((u32)(map != GX_TEXMAP_NULL && !(map & GX_TEX_DISABLE)) << 6);
    }

    GX_WRITE_RAS_REG(*ptref);
    __GXData->bpSentNot = 0;
    __GXData->dirtyState |= 1;
}

void GXSetNumTevStages(u8 nStages) {
    u32 reg;

    CHECK_GXBEGIN(1187, "GXSetNumTevStages");

    ASSERTMSGLINE(1189, nStages != 0 && nStages <= 16, "GXSetNumTevStages: Exceed max number of tex stages");
    reg = __GXData->genMode;
    reg = (reg & 0xFFFFC3FF) | (((nStages & 0xFF) - 1) << 10);
    __GXData->genMode = reg;
    __GXData->dirtyState |= 4;
}
