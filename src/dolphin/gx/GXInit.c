#include <string.h>

#include <dolphin/base/PPCArch.h>
#include <dolphin/gx.h>
#include <dolphin/os.h>
#include <dolphin/vi.h>

#include "dolphin/gx/__gx.h"

#if DEBUG
static const char s___GXVersion[] = "<< Dolphin SDK - GX\tdebug build: Apr  5 2004 03:55:13 (0x2301) >>";
#else
extern const char s___GXVersion[];
#endif
const char* __GXVersion = s___GXVersion;

static GXData gxData;
static GXFifoObj FifoObj;
GXData* const gx = &gxData;
#define __GXData gx
const GXColor GXInit_ClearColor = {64, 64, 64, 255};
const GXColor GXInit_BlackColor = {0, 0, 0, 0};
const GXColor GXInit_WhiteColor = {255, 255, 255, 255};
extern const f32 GXInit_ZeroF;
extern const f32 GXInit_OneF;
extern const f32 GXInit_PointOneF;

const f64 GXInit_IntToFloatBias = 4503599627370496.0;

u32 resetFuncRegistered;
u32 calledOnce;
OSTime time;
u32 peCount;
void* __memReg;
void* __peReg;
void* __cpReg;
void* __piReg;

#if DEBUG
GXBool __GXinBegin;
#endif

static GXVtxAttrFmtList GXDefaultVATList[] = {
    {GX_VA_POS, GX_POS_XYZ, GX_F32, 0},
    {GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0},
    {GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0},
    {GX_VA_CLR1, GX_CLR_RGBA, GX_RGBA8, 0},
    {GX_VA_TEX0, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX1, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX2, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX3, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX4, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX5, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX6, GX_TEX_ST, GX_F32, 0},
    {GX_VA_TEX7, GX_TEX_ST, GX_F32, 0},
    {GX_VA_NULL, 0, 0, 0},
};

// prototypes
static int __GXShutdown(int final);

static OSResetFunctionInfo GXResetFuncInfo = {__GXShutdown, 0x7F, NULL, NULL};

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
static GXTexRegion* __GXDefaultTexRegionCallback(const GXTexObj* t_obj, GXTexMapID id) {
    GXTexFmt format = GXGetTexObjFmt(t_obj);

    (void)id;

    if (format != 8) {
        if (format != 9) {
            if (format != 10) {
                return &__GXData->TexRegions0[__GXData->nextTexRgn++ & 7];
            }
        }
    }

    return &__GXData->TexRegions1[__GXData->nextTexRgnCI++ & 3];
}

static GXTlutRegion* __GXDefaultTlutRegionCallback(u32 idx) {
    if (idx >= 20) {
        return NULL;
    }
    return &__GXData->TlutRegions[idx];
}

#if DEBUG
static void __GXDefaultVerifyCallback(GXWarningLevel level, u32 id, const char* msg) {
    OSReport("Level %1d, Warning %3d: %s\n", level, id, msg);
}
#endif

static int __GXShutdown(BOOL final) {
    u32 reg;
    u32 peCountNew;
    OSTime timeNew;

    if (!final) {
        if (!calledOnce) {
            peCount = __GXReadMEMCounterU32(0x28, 0x27);
            time = OSGetTime();
            calledOnce = 1;
            return 0;
        }

        timeNew = OSGetTime();
        peCountNew = __GXReadMEMCounterU32(0x28, 0x27);

        if (timeNew - time < 10) {
            return 0;
        }

        if (peCountNew != peCount) {
            peCount = peCountNew;
            time = timeNew;
            return 0;
        }

    } else {
        GXSetBreakPtCallback(NULL);
        GXSetDrawSyncCallback(NULL);
        GXSetDrawDoneCallback(NULL);

        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);
        GX_WRITE_U32(0);

        PPCSync();

        reg = 0;
        GX_SET_CP_REG(1, reg);

        reg = 3;
        GX_SET_CP_REG(2, reg);

        __GXData->abtWaitPECopy = 1;

        __GXAbort();
    }

    return 1;
}

GXFifoObj* GXInit(void* base, u32 size) {
    u32 i;
    u32 reg;
    u32 freqBase;
    u8 stackPadding[8];

    OSRegisterVersion(__GXVersion);

    __GXData->inDispList = FALSE;
    __GXData->dlSaveContext = TRUE;
    __GXData->abtWaitPECopy = 1;
#if DEBUG
    __GXinBegin = FALSE;
#endif
    __GXData->tcsManEnab = FALSE;
    __GXData->tevTcEnab = FALSE;
    
    GXSetMisc(GX_MT_XF_FLUSH, 0);

    __piReg = OSPhysicalToUncached(0xC003000);
    __cpReg = OSPhysicalToUncached(0xC000000);
    __peReg = OSPhysicalToUncached(0xC001000);
    __memReg = OSPhysicalToUncached(0xC004000);
    __GXFifoInit();
    GXInitFifoBase(&FifoObj, base, size);
    GXSetCPUFifo(&FifoObj);
    GXSetGPFifo(&FifoObj);

    if (!resetFuncRegistered) {
        OSRegisterResetFunction(&GXResetFuncInfo);
        resetFuncRegistered = 1;
    }

    __GXPEInit();
    {
        u32 hid2 = PPCMfhid2();

        PPCMtwpar(OSUncachedToPhysical((void*)GXFIFO_ADDR));
        hid2 |= 0x40000000;
        PPCMthid2(hid2);
    }

    __GXData->genMode = 0;
    SET_REG_FIELD(0, __GXData->genMode, 8, 24, 0);
    __GXData->bpMask = 255;
    SET_REG_FIELD(0, __GXData->bpMask, 8, 24, 0x0F);
    __GXData->lpSize = 0;
    SET_REG_FIELD(0, __GXData->lpSize, 8, 24, 0x22);

    for (i = 0; i < 16; ++i) {
        __GXData->tevc[i] = 0;
        __GXData->teva[i] = 0;
        __GXData->tref[i / 2] = 0;
        __GXData->texmapId[i] = GX_TEXMAP_NULL;
        SET_REG_FIELD(1130, __GXData->tevc[i], 8, 24, 0xC0 + i * 2);
        SET_REG_FIELD(1131, __GXData->teva[i], 8, 24, 0xC1 + i * 2);
        SET_REG_FIELD(1133, __GXData->tevKsel[i / 2], 8, 24, 0xF6 + i / 2);
        SET_REG_FIELD(1135, __GXData->tref[i / 2], 8, 24, 0x28 + i / 2);
    }

    __GXData->iref = 0;
    SET_REG_FIELD(0, __GXData->iref, 8, 24, 0x27);

    for (i = 0; i < 8; ++i) {
        __GXData->suTs0[i] = 0;
        __GXData->suTs1[i] = 0;
        SET_REG_FIELD(1144, __GXData->suTs0[i], 8, 24, 0x30 + i * 2);
        SET_REG_FIELD(1145, __GXData->suTs1[i], 8, 24, 0x31 + i * 2);
    }

    SET_REG_FIELD(0, __GXData->suScis0, 8, 24, 0x20);
    SET_REG_FIELD(0, __GXData->suScis1, 8, 24, 0x21);
    SET_REG_FIELD(0, __GXData->cmode0, 8, 24, 0x41);
    SET_REG_FIELD(0, __GXData->cmode1, 8, 24, 0x42);
    SET_REG_FIELD(0, __GXData->zmode, 8, 24, 0x40);
    SET_REG_FIELD(0, __GXData->peCtrl, 8, 24, 0x43);
    SET_REG_FIELD(0, __GXData->cpTex, 2, 7, 0);

    __GXData->dirtyState = 0;
    __GXData->dirtyVAT = FALSE;

#if DEBUG
    __gxVerif->verifyLevel = GX_WARN_NONE;
    GXSetVerifyCallback((GXVerifyCallback)__GXDefaultVerifyCallback);
    for (i = 0; i < 256; i++) {
        SET_REG_FIELD(0, __gxVerif->rasRegs[i], 8, 24, 0xFF);
    }
    memset(__gxVerif->xfRegsDirty, 0, 0x50);
    memset(__gxVerif->xfMtxDirty, 0, 0x100);
    memset(__gxVerif->xfNrmDirty, 0, 0x60);
    memset(__gxVerif->xfLightDirty, 0, 0x80);
#endif

    freqBase = __OSBusClock / 500;
    __GXFlushTextureState();
    reg = (freqBase >> 11) | 0x400 | 0x69000000;
    GX_WRITE_RAS_REG(reg);

    __GXFlushTextureState();
    reg = (freqBase / 0x1080) | 0x200 | 0x46000000;
    GX_WRITE_RAS_REG(reg);

    for (i = GX_VTXFMT0; i < GX_MAX_VTXFMT; i++) {
        SET_REG_FIELD(0, __GXData->vatA[i], 1, 30, 1);
        SET_REG_FIELD(0, __GXData->vatB[i], 1, 31, 1);
        {
            s32 regAddr;

            GX_WRITE_U8(0x8);
            GX_WRITE_U8(i | 0x80);
            GX_WRITE_U32(__GXData->vatB[i]);
            regAddr = i - 12;
        }
    }
    {
        u32 reg1 = 0;
        u32 reg2 = 0;

        SET_REG_FIELD(0, reg1, 1, 0, 1);
        SET_REG_FIELD(0, reg1, 1, 1, 1);
        SET_REG_FIELD(0, reg1, 1, 2, 1);
        SET_REG_FIELD(0, reg1, 1, 3, 1);
        SET_REG_FIELD(0, reg1, 1, 4, 1);
        SET_REG_FIELD(0, reg1, 1, 5, 1);
        GX_WRITE_XF_REG(0, reg1);
        SET_REG_FIELD(0, reg2, 1, 0, 1);
        GX_WRITE_XF_REG(0x12, reg2);
#if DEBUG
        __gxVerif->xfRegsDirty[0] = 0;
#endif
    }
    {
        u32 reg1 = 0;

        SET_REG_FIELD(0, reg1, 1, 0, 1);
        SET_REG_FIELD(0, reg1, 1, 1, 1);
        SET_REG_FIELD(0, reg1, 1, 2, 1);
        SET_REG_FIELD(0, reg1, 1, 3, 1);
        SET_REG_FIELD(0, reg1, 8, 24, 0x58);
        GX_WRITE_RAS_REG(reg1);
    }

    for (i = 0; i < 8; i++) {
        GXInitTexCacheRegion(&__GXData->TexRegions0[i], GX_FALSE, i * 0x8000, GX_TEXCACHE_32K,
                             0x80000 + i * 0x8000, GX_TEXCACHE_32K);
    }

    for (i = 0; i < 4; i++) {
        GXInitTexCacheRegion(&__GXData->TexRegions1[i], GX_FALSE, (i * 2 + 8) * 0x8000,
                             GX_TEXCACHE_32K, (i * 2 + 9) * 0x8000, GX_TEXCACHE_32K);
    }

    for (i = 0; i < 16; i++) {
        GXInitTlutRegion(&__GXData->TlutRegions[i], 0xC0000 + 0x2000 * i, GX_TLUT_256);
    }

    for (i = 0; i < 4; i++) {
        GXInitTlutRegion(&__GXData->TlutRegions[i + 16], 0xE0000 + 0x8000 * i, GX_TLUT_1K);
    }

    {
        u32 reg = 0;
#if DEBUG
        s32 regAddr;
#endif
        GX_SET_CP_REG(3, reg);

        SET_REG_FIELD(0, __GXData->perfSel, 4, 4, 0);
        GX_WRITE_U8(0x8);
        GX_WRITE_U8(0x20);
        GX_WRITE_U32(__GXData->perfSel);
#if DEBUG
        regAddr = -12;
#endif
    
        reg = 0;
        GX_WRITE_XF_REG(6, reg);
        
        reg = 0x23000000;
        GX_WRITE_RAS_REG(reg);

        reg = 0x24000000;
        GX_WRITE_RAS_REG(reg);

        reg = 0x67000000;
        GX_WRITE_RAS_REG(reg);
    }

    __GXSetTmemConfig(0);
    __GXInitGX();

    return &FifoObj;
}

void __GXInitGX(void) {
    GXRenderModeObj* rmode;
    float identity_mtx[3][4];
    GXColor clear = GXInit_ClearColor;
    GXColor black = GXInit_BlackColor;
    GXColor white = GXInit_WhiteColor;
    u32 i;

    switch (VIGetTvFormat()) {
    case VI_NTSC:    rmode = &GXNtsc480IntDf; break;
    case VI_PAL:     rmode = &GXPal528IntDf;  break;
    case VI_EURGB60: rmode = &GXEurgb60Hz480IntDf; break;
    case VI_MPAL:    rmode = &GXMpal480IntDf; break;
    default:
        ASSERTMSGLINE(1342, 0, "GXInit: invalid TV format");
        rmode = &GXNtsc480IntDf;
        break;
    }

    GXSetCopyClear(clear, 0xFFFFFF);
    GXSetTexCoordGen(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX1, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX2, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX3, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX4, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD5, GX_TG_MTX2x4, GX_TG_TEX5, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD6, GX_TG_MTX2x4, GX_TG_TEX6, 0x3C);
    GXSetTexCoordGen(GX_TEXCOORD7, GX_TG_MTX2x4, GX_TG_TEX7, 0x3C);
    GXSetNumTexGens(1);
    GXClearVtxDesc();
    GXInvalidateVtxCache();

    for (i = GX_VA_POS; i <= GX_LIGHT_ARRAY; i++) {
        GXSetArray(i, __GXData, 0);
    }

    for (i = GX_VTXFMT0; i < GX_MAX_VTXFMT; i++) {
        GXSetVtxAttrFmtv(i, GXDefaultVATList);
    }

    GXSetLineWidth(6, GX_TO_ZERO);
    GXSetPointSize(6, GX_TO_ZERO);
    GXEnableTexOffsets(GX_TEXCOORD0, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD1, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD2, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD3, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD4, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD5, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD6, 0, 0);
    GXEnableTexOffsets(GX_TEXCOORD7, 0, 0);
    identity_mtx[0][0] = GXInit_OneF;
    identity_mtx[0][1] = GXInit_ZeroF;
    identity_mtx[0][2] = GXInit_ZeroF;
    identity_mtx[0][3] = GXInit_ZeroF;
    identity_mtx[1][0] = GXInit_ZeroF;
    identity_mtx[1][1] = GXInit_OneF;
    identity_mtx[1][2] = GXInit_ZeroF;
    identity_mtx[1][3] = GXInit_ZeroF;
    identity_mtx[2][0] = GXInit_ZeroF;
    identity_mtx[2][1] = GXInit_ZeroF;
    identity_mtx[2][2] = GXInit_OneF;
    identity_mtx[2][3] = GXInit_ZeroF;
    GXLoadPosMtxImm(identity_mtx, GX_PNMTX0);
    GXLoadNrmMtxImm(identity_mtx, GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    GXLoadTexMtxImm(identity_mtx, GX_IDENTITY, GX_MTX3x4);
    GXLoadTexMtxImm(identity_mtx, GX_PTIDENTITY, GX_MTX3x4);
    GXSetViewport(GXInit_ZeroF, GXInit_ZeroF, rmode->fbWidth, rmode->xfbHeight, GXInit_ZeroF, GXInit_OneF);
    GXSetCoPlanar(GX_DISABLE);
    GXSetCullMode(GX_CULL_BACK);
    GXSetClipMode(GX_CLIP_ENABLE);
    GXSetScissor(0, 0, rmode->fbWidth, rmode->efbHeight);
    GXSetScissorBoxOffset(0, 0);
    GXSetNumChans(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR0A0, black);
    GXSetChanMatColor(GX_COLOR0A0, white);
    GXSetChanCtrl(GX_COLOR1A1, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR1A1, black);
    GXSetChanMatColor(GX_COLOR1A1, white);
    GXInvalidateTexAll();
    __GXData->nextTexRgn = 0;
    __GXData->nextTexRgnCI = 0;
    GXSetTexRegionCallback((GXTexRegionCallback)__GXDefaultTexRegionCallback);
    GXSetTlutRegionCallback(__GXDefaultTlutRegionCallback);

    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD2, GX_TEXMAP2, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD3, GX_TEXMAP3, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD4, GX_TEXMAP4, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD5, GX_TEXMAP5, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE6, GX_TEXCOORD6, GX_TEXMAP6, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE7, GX_TEXCOORD7, GX_TEXMAP7, GX_COLOR0A0);
    GXSetTevOrder(GX_TEVSTAGE8, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE9, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE10, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE11, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE12, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE13, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE14, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevOrder(GX_TEVSTAGE15, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);

    GXSetNumTevStages(1);
    GXSetTevOp(GX_TEVSTAGE0, GX_REPLACE);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetZTexture(GX_ZT_DISABLE, GX_TF_Z8, 0);

    for (i = GX_TEVSTAGE0; i < GX_MAX_TEVSTAGE; i++) {
        GXSetTevKColorSel((GXTevStageID)i, GX_TEV_KCSEL_1_4);
        GXSetTevKAlphaSel((GXTevStageID)i, GX_TEV_KASEL_1);
        GXSetTevSwapMode((GXTevStageID)i, GX_TEV_SWAP0, GX_TEV_SWAP0);
    }

    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    for (i = GX_TEVSTAGE0; i < GX_MAX_TEVSTAGE; i++)
        GXSetTevDirect((GXTevStageID)i);

    GXSetNumIndStages(0);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE2, GX_ITS_1, GX_ITS_1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE3, GX_ITS_1, GX_ITS_1);

    GXSetFog(GX_FOG_NONE, GXInit_ZeroF, GXInit_OneF, GXInit_PointOneF, GXInit_OneF, black);
    GXSetFogRangeAdj(GX_DISABLE, 0, NULL);
    GXSetBlendMode(GX_BM_NONE, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_CLEAR);
    GXSetColorUpdate(GX_ENABLE);
    GXSetAlphaUpdate(GX_ENABLE);
    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
    GXSetZCompLoc(GX_TRUE);
    GXSetDither(GX_ENABLE);
    GXSetDstAlpha(GX_DISABLE, 0);
    GXSetPixelFmt(GX_PF_RGB8_Z24, GX_ZC_LINEAR);
    GXSetFieldMask(GX_ENABLE, GX_ENABLE);
    GXSetFieldMode(rmode->field_rendering,
                   ((rmode->viHeight == 2 * rmode->xfbHeight) ? GX_ENABLE : GX_DISABLE));

    GXSetDispCopySrc(0, 0, rmode->fbWidth, rmode->efbHeight);
    GXSetDispCopyDst(rmode->fbWidth, rmode->efbHeight);
    GXSetDispCopyYScale((f32)(rmode->xfbHeight) / (f32)(rmode->efbHeight));
    GXSetCopyClamp((GXFBClamp)(GX_CLAMP_TOP | GX_CLAMP_BOTTOM));
    GXSetCopyFilter(rmode->aa, rmode->sample_pattern, GX_TRUE, rmode->vfilter);
    GXSetDispCopyGamma(GX_GM_1_0);
    GXSetDispCopyFrame2Field(GX_COPY_PROGRESSIVE);
    GXClearBoundingBox();

    GXPokeColorUpdate(GX_TRUE);
    GXPokeAlphaUpdate(GX_TRUE);
    GXPokeDither(GX_FALSE);
    GXPokeBlendMode(GX_BM_NONE, GX_BL_ZERO, GX_BL_ONE, GX_LO_SET);
    GXPokeAlphaMode(GX_ALWAYS, 0);
    GXPokeAlphaRead(GX_READ_FF);
    GXPokeDstAlpha(GX_DISABLE, 0);
    GXPokeZMode(GX_TRUE, GX_ALWAYS, GX_TRUE);

    GXSetGPMetric(GX_PERF0_NONE, GX_PERF1_NONE);
    GXClearGPMetric();
}

const f32 GXInit_ZeroF = 0.0f;
const f32 GXInit_OneF = 1.0f;
const f32 GXInit_PointOneF = 0.1f;
