#include <stddef.h>
#include <dolphin/hw_regs.h>
#include <dolphin/base/PPCArch.h>
#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

extern GXData* gx;
#define __GXData gx

extern GXDrawSyncCallback __CARDEncode;
extern GXDrawDoneCallback lbl_803DE0DC;
extern u8 lbl_803DE0E0;
extern OSThreadQueue lbl_803DE0E4;

#define TokenCB __CARDEncode
#define DrawDoneCB lbl_803DE0DC
#define DrawDone lbl_803DE0E0
#define FinishQueue lbl_803DE0E4

void GXSetMisc(GXMiscToken token, u32 val) {
    if (token == GX_MT_XF_FLUSH) {
        goto case1;
    }
    if (token < GX_MT_XF_FLUSH) {
        goto out;
    }
    if (token >= 3) {
        goto out;
    }
    goto case2;

case1:
    gx->vNum = val;
    gx->vNumNot = !gx->vNum;
    gx->bpSentNot = 1;

    if (gx->vNum != 0) {
        gx->dirtyState |= 8;
    }
    goto out;

case2:
    gx->dlSaveContext = (val != 0);
out:;
}

void GXFlush(void) {
    CHECK_GXBEGIN(270, "GXFlush");
    if (__GXData->dirtyState) {
        __GXSetDirtyState();
    }

    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);

    PPCSync();
}

void GXResetWriteGatherPipe(void) {
    while (PPCMfwpar() & 1) {
    }
    PPCMtwpar(OSUncachedToPhysical((void*)GXFIFO_ADDR));
}

#if SDK_REVISION >= 1
static inline void __GXAbortWait(u32 clocks) {
    OSTime time0;
    OSTime time1;

    time0 = OSGetTime();
    do {
        time1 = OSGetTime();
    } while (time1 - time0 <= (clocks / 4));
}
#endif

void __GXAbortWaitPECopyDone(void) {
    OSTime time0;
    OSTime time1;

    ((volatile u32*)__piReg)[0x18 / 4] = 1;
    time0 = OSGetTime();
    do {
        time1 = OSGetTime();
    } while (time1 - time0 <= 50);

    ((volatile u32*)__piReg)[0x18 / 4] = 0;
    time0 = OSGetTime();
    do {
        time1 = OSGetTime();
    } while (time1 - time0 <= 5);

    __GXCleanGPFifo();
}

#if SDK_REVISION >= 1
void __GXAbort(void) {
    if (__GXData->abtWaitPECopy && GXGetGPFifo() != (GXFifoObj*)NULL) {
        __GXAbortWaitPECopyDone();
    }

    __PIRegs[0x18 / 4] = 1;
    __GXAbortWait(200);
    __PIRegs[0x18 / 4] = 0;
    __GXAbortWait(20);
}
#endif

#if SDK_REVISION >= 1
void GXAbortFrame(void) {
    __GXAbort();

    if (GXGetGPFifo() != (GXFifoObj*)NULL) {
        __GXCleanGPFifo();
        __GXInitRevisionBits();
        __GXData->dirtyState = 0;
        GXFlush();
    }
}
#endif

void GXSetDrawSync(u16 token) {
    BOOL enabled;
    u32 reg;

    CHECK_GXBEGIN(430, "GXSetDrawSync");

    enabled = OSDisableInterrupts();
    reg = ((u32)token & 0xFFFF) | 0x48000000;
    GX_WRITE_RAS_REG(reg);
    reg = (reg & ~0xFFFF) | ((u32)token & 0xFFFF);
    reg = (reg & ~0xFF000000) | ((u32)0x47 << 24);
    GX_WRITE_RAS_REG(reg);
    GXFlush();
    OSRestoreInterrupts(enabled);
    __GXData->bpSentNot = 0;
}

u16 GXReadDrawSync(void) {
    u16 token = GX_GET_PE_REG(7);
    return token;
}

#if SDK_REVISION >= 1
void GXSetDrawDone(void) {
    u32 reg;
    BOOL enabled;

    CHECK_GXBEGIN(488, "GXSetDrawDone");
    enabled = OSDisableInterrupts();
    reg = 0x45000002;
    GX_WRITE_RAS_REG(reg);
    GXFlush();
    DrawDone = 0;
    OSRestoreInterrupts(enabled);
}
#endif

#if SDK_REVISION >= 1
void GXWaitDrawDone(void) {
    BOOL enabled;

    CHECK_GXBEGIN(534, "GXWaitDrawDone");

    enabled = OSDisableInterrupts();
    while (!DrawDone) {
        OSSleepThread(&FinishQueue);
    }
    OSRestoreInterrupts(enabled);
}
#endif

#if SDK_REVISION >= 1
void GXDrawDone(void) {
    CHECK_GXBEGIN(566, "GXDrawDone");
    GXSetDrawDone();
    GXWaitDrawDone();
}
#endif

void GXPixModeSync(void) {
    CHECK_GXBEGIN(601, "GXPixModeSync");
    GX_WRITE_RAS_REG(__GXData->peCtrl);
    __GXData->bpSentNot = 0;
}

void GXTexModeSync(void) {
    u32 reg;

    CHECK_GXBEGIN(625, "GXTexModeSync");
    reg = 0x63000000;
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

#if DEBUG
void __GXBypass(u32 reg) {
    CHECK_GXBEGIN(647, "__GXBypass");
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

u16 __GXReadPEReg(u32 reg) {
    return GX_GET_PE_REG(reg);
}
#endif

void GXPokeAlphaMode(GXCompare func, u8 threshold) {
    u32 reg;

    reg = (func << 8) | threshold;
    GX_SET_PE_REG(3, reg);
}

void GXPokeAlphaRead(GXAlphaReadMode mode) {
    GX_SET_PE_REG(4, (mode & 0xFFFFFFFB) | 4);
}

void GXPokeAlphaUpdate(GXBool update_enable) {
    volatile u16* pe_reg;
    u16 reg;

    pe_reg = (volatile u16*)__peReg + 1;
    reg = *pe_reg;
    reg = (reg & ~(1 << 4)) | ((u16)update_enable << 4);
    *pe_reg = reg;
}

void GXPokeBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op) {
    u32 blend_enable;
    u32 subtract_enable;
    u32 logic_enable;
    u32 reg;
    volatile u16* pe_reg_1;

    pe_reg_1 = (volatile u16*)__peReg + 1;
    reg = *pe_reg_1;

    blend_enable = (type == GX_BM_BLEND) || (type == GX_BM_SUBTRACT);
    subtract_enable = (type == GX_BM_SUBTRACT);
    logic_enable = (type == GX_BM_LOGIC);
    reg = (reg & ~0x1) | blend_enable;
    reg = (reg & ~0x800) | (subtract_enable << 11);
    reg = (reg & ~0x2) | (logic_enable << 1);
    reg = (reg & ~0xF000) | ((u32)op << 12);
    reg = (reg & ~0x0700) | ((u32)src_factor << 8);
    reg = (reg & ~0x00E0) | ((u32)dst_factor << 5);
    reg = (reg & 0x00FFFFFF) | 0x41000000;
    *pe_reg_1 = reg;
}

void GXPokeColorUpdate(GXBool update_enable) {
    volatile u16* pe_reg;
    u16 reg;

    pe_reg = (volatile u16*)__peReg + 1;
    reg = *pe_reg;
    reg = (reg & ~(1 << 3)) | ((u16)update_enable << 3);
    *pe_reg = reg;
}

void GXPokeDstAlpha(GXBool enable, u8 alpha) {
    GX_SET_PE_REG(2, (u16)((u16)alpha | ((u16)enable << 8)));
}

void GXPokeDither(GXBool dither) {
    volatile u16* pe_reg;
    u16 reg;

    pe_reg = (volatile u16*)__peReg + 1;
    reg = *pe_reg;
    reg = (reg & ~(1 << 2)) | ((u16)dither << 2);
    *pe_reg = reg;
}

void GXPokeZMode(GXBool compare_enable, GXCompare func, GXBool update_enable) {
    u32 reg = (u32)compare_enable;
    volatile u16* pe_reg = (volatile u16*)__peReg;

    reg = (reg & 0xFFFFFFF1) | ((u32)func << 1);
    reg = (reg & 0xFFFFFFEF) | ((u32)update_enable << 4);
    pe_reg[0] = (u16)reg;
}

#if SDK_REVISION >= 1
void GXPeekARGB(u16 x, u16 y, u32* color) {
    u32 addr = (u32)OSPhysicalToUncached(0x08000000);

    SET_REG_FIELD(792, addr, 10, 2, x);
    SET_REG_FIELD(793, addr, 10, 12, y);
    SET_REG_FIELD(793, addr, 2, 22, 0);
    *color = *(u32*)addr;
}
#endif

#if SDK_REVISION >= 1
void GXPokeARGB(u16 x, u16 y, u32 color) {
    u32 addr = (u32)OSPhysicalToUncached(0x08000000);

    SET_REG_FIELD(0x322, addr, 10, 2, x);
    SET_REG_FIELD(0x323, addr, 10, 12, y);
    SET_REG_FIELD(0x323, addr, 2, 22, 0);
    *(u32*)addr = color;
}
#endif

void GXPeekZ(u16 x, u16 y, u32* z) {
    u32 addr;

    addr = (u32)OSPhysicalToUncached(0x08000000);
    addr = (addr & ~(0x3FF << 2)) | ((u32)x << 2);
    addr = (addr & ~(0x3FF << 12)) | ((u32)y << 12);
    addr = (addr & ~(0x3 << 22)) | (1 << 22);
    *z = *(u32*)addr;
}

#if SDK_REVISION >= 1
void GXPokeZ(u16 x, u16 y, u32 z) {
    u32 addr = (u32)OSPhysicalToUncached(0x08000000);

    SET_REG_FIELD(822, addr, 10, 2, x);
    SET_REG_FIELD(823, addr, 10, 12, y);
    SET_REG_FIELD(823, addr, 2, 22, 1);
    *(u32*)addr = z;
}
#endif

#if SDK_REVISION >= 1
GXDrawSyncCallback GXSetDrawSyncCallback(GXDrawSyncCallback cb) {
    GXDrawSyncCallback oldcb;
    BOOL enabled;

    oldcb = TokenCB;
    enabled = OSDisableInterrupts();
    TokenCB = cb;
    OSRestoreInterrupts(enabled);
    return oldcb;
}
#endif

static void GXTokenInterruptHandler(__OSInterrupt interrupt, OSContext* context) {
    u16 token;
    OSContext exceptionContext;
    volatile u16* peReg;
    u16 reg;

    token = GX_GET_PE_REG(7);
    if (TokenCB != NULL) {
        OSClearContext(&exceptionContext);
        OSSetCurrentContext(&exceptionContext);
        TokenCB(token);
        OSClearContext(&exceptionContext);
        OSSetCurrentContext(context);
    }
    peReg = (volatile u16*)__peReg + 5;
    reg = *peReg;
    reg = (reg & ~(1 << 2)) | (1 << 2);
    *peReg = reg;
}

#if SDK_REVISION >= 1
GXDrawDoneCallback GXSetDrawDoneCallback(GXDrawDoneCallback cb) {
    GXDrawDoneCallback oldcb;
    BOOL enabled;

    oldcb = DrawDoneCB;
    enabled = OSDisableInterrupts();
    DrawDoneCB = cb;
    OSRestoreInterrupts(enabled);
    return oldcb;
}
#endif

static void GXFinishInterruptHandler(__OSInterrupt interrupt, OSContext* context) {
    OSContext exceptionContext;
    volatile u16* peReg;
    u16 reg;

    peReg = (volatile u16*)__peReg + 5;
    reg = *peReg;
    reg = (reg & ~(1 << 3)) | (1 << 3);
    *peReg = reg;
    DrawDone = 1;
    if (DrawDoneCB != NULL) {
        OSClearContext(&exceptionContext);
        OSSetCurrentContext(&exceptionContext);
        DrawDoneCB();
        OSClearContext(&exceptionContext);
        OSSetCurrentContext(context);
    }
    OSWakeupThread(&FinishQueue);
}

void __GXPEInit(void) {
    u16 reg;

    __OSSetInterruptHandler(0x12, GXTokenInterruptHandler);
    __OSSetInterruptHandler(0x13, GXFinishInterruptHandler);
    OSInitThreadQueue(&FinishQueue);
    __OSUnmaskInterrupts(0x2000);
    __OSUnmaskInterrupts(0x1000);
    reg = GX_GET_PE_REG(5);
    reg = (reg & ~(1 << 2)) | (1 << 2);
    reg = (reg & ~(1 << 3)) | (1 << 3);
    reg = (reg & ~(1 << 0)) | (1 << 0);
    reg = (reg & ~(1 << 1)) | (1 << 1);
    GX_SET_PE_REG(5, reg);
}

#if SDK_REVISION >= 1
u32 GXCompressZ16(u32 z24, GXZFmt16 zfmt) {
    u32 z16;
    u32 z24n;
    s32 exp;
    s32 shift;
#if DEBUG
#define temp exp
#else
    s32 temp;
    u8 unused[4];
#endif

    z24n = ~(z24 << 8);
    temp = __cntlzw(z24n);
    switch (zfmt) {
    case GX_ZC_LINEAR:
        z16 = (z24 >> 8) & 0xFFFF;
        break;
    case GX_ZC_NEAR:
        if (temp > 3) {
            exp = 3;
        } else {
            exp = temp;
        }
        if (exp == 3) {
            shift = 7;
        } else {
            shift = 9 - exp;
        }
        z16 = ((z24 >> shift) & 0x3FFF & ~0xFFFFC000) | (exp << 14);
        break;
    case GX_ZC_MID:
        if (temp > 7) {
            exp = 7;
        } else {
            exp = temp;
        }
        if (exp == 7) {
            shift = 4;
        } else {
            shift = 10 - exp;
        }
        z16 = ((z24 >> shift) & 0x1FFF & ~0xFFFFE000) | (exp << 13);
        break;
    case GX_ZC_FAR:
        if (temp > 12) {
            exp = 12;
        } else {
            exp = temp;
        }
        if (exp == 12) {
            shift = 0;
        } else {
            shift = 11 - exp;
        }
        z16 = ((z24 >> shift) & 0xFFF & ~0xFFFFF000) | (exp << 12);
        break;
    default:
        OSPanic(__FILE__, 1004, "GXCompressZ16: Invalid Z format\n");
        break;
    }
    return z16;
}
#endif

#if SDK_REVISION >= 1
u32 GXDecompressZ16(u32 z16, GXZFmt16 zfmt) {
    u32 z24;
    u32 cb1;
    s32 exp;
    s32 shift;

    cb1; cb1; cb1; z16; z16; z16;  // needed to match

    switch (zfmt) {
    case GX_ZC_LINEAR:
        z24 = (z16 << 8) & 0xFFFF00;
        break;
    case GX_ZC_NEAR:
        exp = (z16 >> 14) & 3;
        if (exp == 3) {
            shift = 7;
        } else {
            shift = 9 - exp;
        }
        cb1 = -1 << (24 - exp);
        z24 = (cb1 | ((z16 & 0x3FFF) << shift)) & 0xFFFFFF;
        break;
    case GX_ZC_MID:
        exp = (z16 >> 13) & 7;
        if (exp == 7) {
            shift = 4;
        } else {
            shift = 10 - exp;
        }
        cb1 = -1 << (24 - exp);
        z24 = (cb1 | ((z16 & 0x1FFF) << shift)) & 0xFFFFFF;
        break;
    case GX_ZC_FAR:
        exp = (z16 >> 12) & 0xF;
        if (exp == 12) {
            shift = 0;
        } else {
            shift = 11 - exp;
        }
        cb1 = -1 << (24 - exp);
        z24 = (cb1 | ((z16 & 0xFFF) << shift)) & 0xFFFFFF;
        break;
    default:
        OSPanic(__FILE__, 1054, "GXDecompressZ16: Invalid Z format\n");
        break;
    }
    return z24;
}
#endif
