#include "dolphin/os/OSReport.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
#include "main/newshadows.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSStopwatch.h"
#include "string.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/os/OSResetSW.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXPerf.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/os/OSTime.h"
#include "dolphin/vi.h"
#include "main/camera.h"
#include "main/debug.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/table_file.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath_distance_api.h"
#include "main/zlb.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"

extern u8 lbl_803DCD00;
extern int lbl_803DCCFC;
extern u8 lbl_803DCCF8;
extern int lbl_803DCCF4;
extern GXRenderModeObj* gRenderModeObj;
extern void* externalFrameBuffer0;
extern void* externalFrameBuffer1;
extern void* lbl_803DCCE4;
extern char* lbl_803DCCE0;
extern void* lbl_803DCCD8;
extern GXFifoObj* lbl_803DCCD4;
extern void* renderFrameBuffer;
extern void* displayFrameBuffer;
extern char lbl_803DCCC4;
extern int lbl_803DCCB8;
extern GXColor lbl_803DB5D0;
extern u8 lbl_803DB5D4[8];
extern u8 gLoadingScreenTextures[];
extern char lbl_8035F6B8[0x78];
extern RingBufferQueue lbl_8035F730;
extern f32 lbl_803DEA94;
extern f32 lbl_803DEA98;

void videoSwapFrameBuffers(u32 retraceCount);
void gpuErrorHandler(u32 retraceCount);
void videoFn_800499e8(void);

extern f32 lbl_803DEA70;
extern f32 lbl_803DEA78;
extern f32 lbl_803DEA88;
extern f32 lbl_803DEA8C;
extern f32 lbl_803DEA90;
extern Mtx44 hudMatrix;

void initViewport(void)
{
    C_MTXOrtho(hudMatrix, lbl_803DEA70, lbl_803DEA88, *(f32*)&lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
}
void videoInit(void* wpad0, int wpad1)
{
    GXFifoObj fifo;
    f32 mtx[3][4];
    GXColor cc;
    u8* arenaLo;
    u8* arenaHi;
    u8* nextArenaLo;
    u32 fifoSize;
    int fbSize;
    arenaLo = OSGetArenaLo();
    arenaHi = OSGetArenaHi();
    memcpy(arenaHi - 0x40000, gLoadingScreenTextures, 0x40000);
    DCStoreRange(arenaHi - 0x40000, 0x40000);
    fifoSize = 0x40000;
    lbl_803DCCE4 = (void*)fifoSize;
    lbl_803DCCD8 = gLoadingScreenTextures;
    DCInvalidateRange(lbl_803DCCD8, fifoSize);
    lbl_803DCCD4 = GXInit(lbl_803DCCD8, (u32)lbl_803DCCE4);
    lbl_803DCCE0 = lbl_803DCCD8;
    GXSetDispCopySrc(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    lbl_803DCCB8 = GXSetDispCopyYScale((f32)gRenderModeObj->xfbHeight / gRenderModeObj->efbHeight);
    fbSize = (u16)((gRenderModeObj->fbWidth + 0xf) & ~0xf) * lbl_803DCCB8 * 2;
    externalFrameBuffer0 = (void*)(((u32)arenaLo + 0x1f) & ~0x1f);
    fbSize += 0x1f;
    externalFrameBuffer1 = (void*)(((u32)externalFrameBuffer0 + fbSize) & ~0x1f);
    nextArenaLo = (u8*)(((u32)externalFrameBuffer1 + fbSize) & ~0x1f);
    OSSetArenaLo(nextArenaLo);
    arenaLo = OSInitAlloc(nextArenaLo, arenaHi, 1);
    OSSetArenaLo(arenaLo);
    arenaLo = (u8*)(((u32)arenaLo + 0x1f) & ~0x1f);
    arenaHi = (u8*)((u32)arenaHi & ~0x1f);
    OSSetCurrentHeap(OSCreateHeap(arenaLo, arenaHi));
    VIConfigure(gRenderModeObj);
    GXInitFifoBase(&fifo, externalFrameBuffer0, 0x10000);
    GXSetCPUFifo(&fifo);
    GXSetGPFifo(&fifo);
    GXInitFifoLimits(lbl_803DCCD4, (u32)lbl_803DCCE4 - 0x4000, (u32)((u32)lbl_803DCCE4 * 3) >> 2);
    GXSetCPUFifo(lbl_803DCCD4);
    GXSetGPFifo(lbl_803DCCD4);
    Queue_Init(&lbl_8035F730, lbl_8035F6B8, 10, 0xc);
    OSInitThreadQueue((OSThreadQueue*)&lbl_803DCCC4);
    VISetPreRetraceCallback(videoSwapFrameBuffers);
    VISetPostRetraceCallback(gpuErrorHandler);
    GXSetBreakPtCallback(videoFn_800499e8);
    GXSetViewport(lbl_803DEA70, lbl_803DEA70, gRenderModeObj->fbWidth, gRenderModeObj->xfbHeight, lbl_803DEA70,
                  lbl_803DEA78);
    GXSetFieldMode(gRenderModeObj->field_rendering, gRenderModeObj->xfbHeight < gRenderModeObj->viHeight);
    GXSetScissor(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    GXSetDispCopyDst(gRenderModeObj->fbWidth, (u16)lbl_803DCCB8);
    if (gRenderModeObj->aa != 0)
    {
        GXSetPixelFmt(GX_PF_RGB565_Z16, GX_ZC_LINEAR);
        GXSetDither(GX_TRUE);
    }
    else
    {
        GXSetPixelFmt(GX_PF_RGB8_Z24, GX_ZC_LINEAR);
        GXSetDither(GX_FALSE);
    }
    displayFrameBuffer = externalFrameBuffer0;
    renderFrameBuffer = externalFrameBuffer1;
    VISetNextFrameBuffer(displayFrameBuffer);
    GXSetDispCopyGamma(GX_GM_1_0);
    VISetBlack(1);
    VIFlush();
    VIWaitForRetrace();
    VIWaitForRetrace();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_POS, GX_POS_XYZ, GX_S16, 0);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT0, GX_VA_TEX0, GX_TEX_ST, GX_S16, 7);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_POS, GX_POS_XYZ, GX_S16, 2);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT1, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT2, GX_VA_TEX1, GX_TEX_ST, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_POS, GX_POS_XYZ, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_NBT, GX_NRM_NBT, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT3, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_TEX0, GX_TEX_ST, GX_S16, 7);
    GXSetVtxAttrFmt(GX_VTXFMT4, GX_VA_NRM, GX_NRM_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_POS, GX_POS_XYZ, GX_S16, 3);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX0, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX1, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX2, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT5, GX_VA_TEX3, GX_TEX_ST, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_POS, GX_POS_XYZ, GX_S16, 8);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT6, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_POS, GX_POS_XYZ, GX_S16, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_NRM, GX_NRM_XYZ, GX_S8, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA4, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX0, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX1, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX2, GX_TEX_ST, GX_S16, 10);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_TEX3, GX_TEX_ST, GX_S16, 10);
    lbl_803DCCF4 = 0;
    GXSetCullMode(GX_CULL_NONE);
    cc = lbl_803DB5D0;
    GXSetCopyClear(cc, 0xffffff);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    GXSetNumChans(1);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    lbl_803DCD00 = 1;
    lbl_803DCCFC = 3;
    lbl_803DCCF8 = 1;
    gxSetZMode_(1, GX_LEQUAL, 1);
    gxSetPeControl_ZCompLoc_(1);
    GXEnableTexOffsets(0, 1, 1);
    PSMTXIdentity(mtx);
    GXLoadPosMtxImm(mtx, GX_PNMTX0);
    GXLoadTexMtxImm(mtx, GX_TEXMTX0, GX_MTX3x4);
    GXLoadTexMtxImm(mtx, GX_TEXMTX1, GX_MTX3x4);
    GXSetCurrentMtx(GX_PNMTX0);
    C_MTXOrtho(hudMatrix, lbl_803DEA94, lbl_803DEA98, lbl_803DEA70, lbl_803DEA8C, lbl_803DEA78, lbl_803DEA90);
    GXSetMisc(GX_MT_XF_FLUSH, 8);
    PPCMtmsr(PPCMfmsr() | MSR_PM);
    PPCMthid0(PPCMfhid0() | HID0_SPD);
}

void setColor_803db5d0(u8 r, u8 g, u8 b)
{
    lbl_803DB5D0.r = r;
    lbl_803DB5D0.g = g;
    lbl_803DB5D0.b = b;
}

extern int lbl_803DCD88;
extern int lbl_803DCD8C;
extern int lbl_803DCD90;
extern u8 lbl_803DCD6A;
void setDisplayCopyFilter(void)
{
    GXRenderModeObj* renderMode = gRenderModeObj;
    if (renderMode == &GXNtsc480Prog || renderMode->field_rendering != 0)
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_FALSE, renderMode->vfilter);
    }
    else
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_TRUE, lbl_803DB5D4);
    }
}
