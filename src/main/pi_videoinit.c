#include "dolphin/os/OSReport.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "game/objects/object.h"
#include "sys/objects.h"
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
#include "track/intersect_hud_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXFifo.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/vi/vifuncs.h"


void videoSwapFrameBuffers(u32 retraceCount);
void gpuErrorHandler(u32 retraceCount);
void videoBreakPointCallback(void);


void initViewport(void)
{
    C_MTXOrtho(hudMatrix, 0.0f, 480.0f, 0.0f, 640.0f, 1.0f, 100.0f);
}
void videoInit(void* unusedRenderMode, int unusedArg)
{
    GXFifoObj fifo;
    Mtx mtx;
    u8* arenaLo;
    u8* arenaHi;
    u32 fbSize;
    arenaLo = OSGetArenaLo();
    arenaHi = OSGetArenaHi();
    memcpy(arenaHi - 0x40000, gLoadingScreenTextures, 0x40000);
    DCStoreRange(arenaHi - 0x40000, 0x40000);
    gGxFifoSize = 0x40000;
    gGxFifoBase = gLoadingScreenTextures;
    DCInvalidateRange(gGxFifoBase, gGxFifoSize);
    gGxFifoObj = GXInit(gGxFifoBase, gGxFifoSize);
    lbl_803DCCE0 = gGxFifoBase;
    GXSetDispCopySrc(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    gDispCopyYScaleLines = GXSetDispCopyYScale((f32)gRenderModeObj->xfbHeight / gRenderModeObj->efbHeight);
    fbSize = (u16)((gRenderModeObj->fbWidth + 0xf) & ~0xf) * gDispCopyYScaleLines * 2;
    externalFrameBuffer0 = (void*)(((u32)arenaLo + 0x1f) & ~0x1f);
    fbSize += 0x1f;
    externalFrameBuffer1 = (void*)(((u32)externalFrameBuffer0 + fbSize) & ~0x1f);
    arenaLo = (u8*)(((u32)externalFrameBuffer1 + fbSize) & ~0x1f);
    OSSetArenaLo(arenaLo);
    arenaLo = OSInitAlloc(arenaLo, arenaHi, 1);
    OSSetArenaLo(arenaLo);
    arenaLo = (u8*)(((u32)arenaLo + 0x1f) & ~0x1f);
    arenaHi = (u8*)((u32)arenaHi & ~0x1f);
    OSSetCurrentHeap(OSCreateHeap(arenaLo, arenaHi));
    VIConfigure(gRenderModeObj);
    GXInitFifoBase(&fifo, externalFrameBuffer0, 0x10000);
    GXSetCPUFifo(&fifo);
    GXSetGPFifo(&fifo);
    GXInitFifoLimits(gGxFifoObj, gGxFifoSize - 0x4000, (gGxFifoSize * 3) >> 2);
    GXSetCPUFifo(gGxFifoObj);
    GXSetGPFifo(gGxFifoObj);
    Queue_Init(&gVideoFlipQueue, gVideoFlipQueueBuffer, 10, 3 * sizeof(void*));
    OSInitThreadQueue((OSThreadQueue*)&gVideoFlipWaitQueue);
    VISetPreRetraceCallback(videoSwapFrameBuffers);
    VISetPostRetraceCallback(gpuErrorHandler);
    GXSetBreakPtCallback(videoBreakPointCallback);
    GXSetViewport(0.0f, 0.0f, gRenderModeObj->fbWidth, gRenderModeObj->xfbHeight, 0.0f,
                  1.0f);
    GXSetFieldMode(gRenderModeObj->field_rendering, gRenderModeObj->xfbHeight < gRenderModeObj->viHeight);
    GXSetScissor(0, 0, gRenderModeObj->fbWidth, gRenderModeObj->efbHeight);
    GXSetDispCopyDst(gRenderModeObj->fbWidth, gDispCopyYScaleLines);
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
    GXSetCopyClear(gEfbCopyClearColor, 0xffffff);
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
    C_MTXOrtho(hudMatrix, -23.0f, 502.0f, 0.0f, 640.0f, 1.0f, 100.0f);
    GXSetMisc(GX_MT_XF_FLUSH, 8);
    /* Mark performance-monitor events and disable speculative cache access. */
    PPCMtmsr(PPCMfmsr() | MSR_PM);
    PPCMthid0(PPCMfhid0() | HID0_SPD);
}

void videoSetEfbCopyClearColor(u8 r, u8 g, u8 b)
{
    gEfbCopyClearColor.r = r;
    gEfbCopyClearColor.g = g;
    gEfbCopyClearColor.b = b;
}

void setDisplayCopyFilter(void)
{
    GXRenderModeObj* renderMode = gRenderModeObj;
    if (renderMode == &GXNtsc480Prog || renderMode->field_rendering != 0)
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_FALSE, renderMode->vfilter);
    }
    else
    {
        GXSetCopyFilter(renderMode->aa, renderMode->sample_pattern, GX_TRUE, gDispCopyFilterWeights);
    }
}


#include "main/dll/ppcwgpipe_struct.h"
extern volatile PPCWGPipe GXWGFifo : (0xCC008000);

int GXFlush_(u8 visible, int unused)
{
    void* fifo_get;
    void* fifo_put;
    void* item[3];
    int s;
    void* next;
    gxSetZMode_(1, GX_LEQUAL, 1);
    GXSetAlphaUpdate(GX_TRUE);
    GXFlush();
    GXGetFifoPtrs(gGxFifoObj, &fifo_get, &fifo_put);
    item[0] = fifo_put;
    item[1] = 0;
    item[2] = renderFrameBuffer;
    s = OSDisableInterrupts();
    Queue_Push(&gVideoFlipQueue, item);
    if (gGxBreakPtEnabled == 0)
    {
        GXEnableBreakPt(fifo_put);
        gGxBreakPtEnabled = 1;
    }
    OSRestoreInterrupts(s);
    GXSetDrawSync(gGxDrawSyncToken);
    GXCopyDisp(renderFrameBuffer, 1);
    GXFlush();
    gGxDrawSyncToken = gGxDrawSyncToken + 1;
    if (renderFrameBuffer == (next = externalFrameBuffer0))
    {
        next = externalFrameBuffer1;
    }
    renderFrameBuffer = next;
    if (visible != 0 && gVideoBlackScreenFrameCount != 0)
    {
        gVideoBlackScreenFrameCount--;
        if (gVideoBlackScreenFrameCount == 0)
        {
            VISetBlack(0);
            gVideoBlackScreenFrameCount = 0;
        }
    }
    return 0;
}



void videoBlackScreenForFrames(int frameCount)
{
    int frames = frameCount;
    VISetBlack(1);
    VIFlush();
    gVideoBlackScreenFrameCount = frames;
}
void logGpuHang(void);
void gxSetGPMetricsEnabled(int enabled);

void logGpuHang(void)
{
    char* strs = (char*)gLoadingScreenTextures;
    u32 topClks, topPerf0, topClks2, topPerf1;
    u32 botClks, botPerf0, botClks2, botPerf1;
    u32 xfStuck;
    u32 cmdStuck;
    u32 rdIdle;
    u32 cmdIdle;
    u8 cmdRdy;
    u8 readIdle;
    u8 fifoErr;
    u8 readIdleVal;

    GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
    GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
    xfStuck = (botClks - topClks) == 0;
    cmdStuck = (botPerf0 - topPerf0) == 0;
    rdIdle = (botClks2 - topClks2) != 0;
    cmdIdle = (botPerf1 - topPerf1) != 0;
    GXGetGPStatus(&fifoErr, &fifoErr, &cmdRdy, &readIdle, &fifoErr);
    OSReport(strs + 0x4002c, cmdRdy, readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
    if (cmdStuck == 0 && rdIdle != 0)
    {
        OSReport(strs + 0x400fc);
    }
    else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x4011c);
    }
    else if ((readIdleVal = readIdle) == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x40144);
    }
    else if (cmdRdy != 0 && readIdleVal != 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0 && cmdIdle != 0)
    {
        OSReport(strs + 0x4016c);
    }
    else
    {
        OSReport(strs + 0x4019c);
    }
}

void gxSetGPMetricsEnabled(int enabled)
{
    if ((u8)enabled != 0)
    {
        GXSetGPMetric(GX_PERF0_NONE, GX_PERF1_NONE);
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x2402c004;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000020;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0x84400;
    }
    else
    {
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x24000000;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000000;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0;
    }
}
void gxDisableGpuHangRecovery(void)
{
    gGpuHangRecoveryEnabled = 0;
    gxSetGPMetricsEnabled(0);
}

char sThreadStateAttrSuspendFormat[] = "thread: state=%d attr=%d suspend=%d\n";

void waitNextFrame(void)
{
    int lvl;
    f32 dt;
    u32 frames;
    u8 step;

    OSStopStopwatch(&gFrameStopwatch);
    gFrameElapsedMs =
        (u64)OSCheckStopwatch(&gFrameStopwatch) / (f32)(u32)((*(u32*)0x800000f8 >> 2) / 1000);
    OSResetStopwatch(&gFrameStopwatch);
    OSStartStopwatch(&gFrameStopwatch);
    timeDelta = 60.0f * (0.001f * gFrameElapsedMs);
    if (gDvdErrorPauseActive != 0)
    {
        timeDelta = 0.0f;
    }
    if (timeDelta > 6.0f)
    {
        timeDelta = 6.0f;
    }
    dt = timeDelta;
    if (dt > 0.1f)
    {
        oneOverTimeDelta = 1.0f / dt;
    }
    else
    {
        oneOverTimeDelta = 1.0f;
    }
    step = (int)(dt + gFrameStepRemainder);
    framesThisStep = step;
    frames = step & 0xff;
    gFrameStepRemainder = (dt + gFrameStepRemainder) - (f32)frames;
    framesThisStepUnclamped = step;
    if (frames < 1)
    {
        framesThisStep = 1;
    }
    lvl = OSDisableInterrupts();
    gVideoWaitThread = OSGetCurrentThread();
    if (gVideoWaitThread->state != OS_THREAD_STATE_RUNNING)
    {
        OSReport(sThreadStateAttrSuspendFormat, gVideoWaitThread->state, gVideoWaitThread->attr,
                 gVideoWaitThread->suspend);
    }
    if ((u32)Queue_GetCount(&gVideoFlipQueue) > 1)
    {
        gGpuStallRetraceCount = 0;
        OSSleepThread((OSThreadQueue*)&gVideoFlipWaitQueue);
    }
    OSRestoreInterrupts(lvl);
    Camera_ApplyFullViewport();
    GXInvalidateVtxCache();
    GXInvalidateTexAll();
}
