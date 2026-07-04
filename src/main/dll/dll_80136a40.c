/*
 * dll_80136a40 - EN v1.0 retargeted system/debug leaves.
 *
 * A grab-bag of low-level support code linked into this DLL:
 *   - The fatal-error display thread (fn_80137DF8) plus its installer
 *     (fn_80137D28 / fn_801388D0): OSSetErrorHandler hooks dump the
 *     exception type, DSISR/SRR0, the stack trace and a full GPR/SPR
 *     register window straight into the external framebuffers, flipping
 *     them forever in a hang loop.
 *   - The debug text subsystem: an in-memory record log (debugPrintf /
 *     debugPrintfxy / debugPrintSetColor write tagged records into
 *     debugLogBuffer) replayed by debugPrintDraw, which lays the log out
 *     twice (measure then draw) and rasterizes glyphs through
 *     fn_80136A40 (per-glyph texture select + textRenderChar) and
 *     fn_80136E00 (record interpreter: color/tab/newline/position tags).
 *   - The title-screen ObjectDescriptor (gTitleScreenObjDescriptor) and
 *     its forwarded callbacks.
 *   - Tricky companion helpers: queued-path particle emission
 *     (Tricky_emitQueuedPathParticles), command-target selection,
 *     blend-channel weight animation and impress/GameBit state pokes.
 *   - Misc object teardown (objAnimFreeChildren) and a minimap timer
 *     readout (fn_80133F70).
 */
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/effect_interfaces.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "stdarg.h"
#include "dolphin/gx/GXCull.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/sfa_extern_decls.h"
#include "dolphin/os/OSCache.h"

typedef struct TrickyImpressState
{
    u8 pad0[0x54 - 0x0];
    u32 flags54;
    u8 pad58[0x408 - 0x58];
    f32 renderPosX;
    f32 renderPosY;
    f32 renderPosZ;
    u8 pad414[0x7A8 - 0x414];
    s32 childObj0; /* 0x7A8: attached child object handle (slot 0) */
    u8 pad7AC[0x7B0 - 0x7AC];
    s32 childObj1; /* 0x7B0: attached child object handle (slot 1) */
    u8 pad7B4[0x7B8 - 0x7B4];
    s32 childObj2; /* 0x7B8: attached child object handle (slot 2) */
    u8 childSlotMap; /* 0x7BC: packed 2-bit slot index per impress child (childObj0/1/2 via >>6/>>4/>>2 & 3) */
    u8 pad7BD[0x808 - 0x7BD];
    f32 unk808;
    u8 pad80C[0x810 - 0x80C];
} TrickyImpressState;

extern u32 ObjGroup_ContainsObject();
extern void* ObjGroup_GetObjects();
extern u64 ObjLink_DetachChild();
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern u32 GameBit_Get(int eventId);
extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32* color);
extern const f32 lbl_803E23E8;
extern void Obj_FreeObject(u8* obj);
extern f32 gDebugInitialScale;
extern f32 gDebugScaleX;
extern f32 gDebugScaleY;
extern u8 gDebugScaleBiasX;
extern u8 gDebugScaleBiasY;
extern void* gDebugFontTex2;
extern void* gDebugFontTex1;
extern void* gDebugFontTex0;
extern void* debugLogEnd;
u8 debugLogBuffer[0x1100];
extern u32 getScreenResolution(void);
extern int gDebugRecordCount;
extern int Sfx_IsPlayingFromObjectChannel(u8*, int);
extern void objAudioFn_800393f8(u8*, u8*, int, int, int, int);
extern int* Obj_GetActiveModel(int obj);
extern f32 lbl_803E2408;
extern f32 timeDelta;
extern u32 gDebugPrintOriginX;
extern u32 gDebugPrintOriginY;
extern u16 debugPrintXpos;
extern u16 debugPrintYpos;
u8 gErrDisplayThread[0x310];
extern s16 gErrExceptionType;
extern u32 gErrContext;
extern u32 lbl_803DDA38;
extern u32 lbl_803DDA34;
extern void OSResumeThread(u8 * thread);
extern void OSSetErrorHandler(int kind, void* handler);
// OSSetErrorHandler() error kinds (OSError)
#define OS_ERROR_SYSTEM_RESET 0
#define OS_ERROR_MACHINE_CHECK 1
#define OS_ERROR_DSI 2
#define OS_ERROR_ISI 3
#define OS_ERROR_ALIGNMENT 5
#define OS_ERROR_PERFORMACE_MONITOR 11
#define OS_ERROR_SYSTEM_INTERRUPT 13
#define OS_ERROR_PROTECTION 15
extern void OSCreateThread(u8* thread, void* entry, void* arg, void* stack_top, int stack_size, int prio, int flags);

u8 gErrDisplayThreadStack[0x1000];
extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int model, int channel, f32 weight);
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E4;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;
extern f32 lbl_803E240C;
extern const f32 lbl_803E2418;
extern f32 getXZDistance(f32* a, f32* b);
extern void Obj_SetModelColorOverrideRecursive(int, int, int, int, int, int);
extern int dll_19_func1B(int p);
extern int* gBaddieControlInterface;
extern f32 fn_8014C5D0(register int obj);
extern f32 vec3f_distanceSquared(int, int);
extern u8 enableDebugText;
extern u16* debugDrawFrameBuffer;

extern u16* externalFrameBuffer1;
extern u16* externalFrameBuffer0;
extern u8 gDebugFontGlyphs[];
extern void selectTexture(char* tex, int slot);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
extern void gxDebugTextureFn_80078c1c(void);
extern u32 gDebugCurrentFontSet;
extern int gDebugDrawPass;
extern f32 gDebugGlyphVScale;
extern f32 gDebugGlyphUScale;
u8 gDebugGlyphMetricsTable[192] = {
    0x02, 0x04, 0x06, 0x08, 0x0A, 0x0F, 0x11, 0x15, 0x17, 0x1F, 0x21, 0x27, 0x29, 0x2B, 0x2D, 0x2F,
    0x31, 0x33, 0x35, 0x38, 0x3A, 0x3F, 0x41, 0x43, 0x45, 0x48, 0x4A, 0x4B, 0x4D, 0x50, 0x52, 0x56,
    0x58, 0x5B, 0x5D, 0x62, 0x64, 0x68, 0x6A, 0x6F, 0x71, 0x76, 0x78, 0x7D, 0x7F, 0x84, 0x86, 0x8B,
    0x8D, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9D, 0xA2, 0xA5, 0xA9, 0xAB, 0xB0, 0xB3, 0xB8, 0x00, 0x01,
    0x00, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x38, 0x3A, 0x41,
    0x43, 0x49, 0x4B, 0x4C, 0x4E, 0x53, 0x55, 0x5B, 0x5D, 0x62, 0x64, 0x6B, 0x6D, 0x73, 0x75, 0x7B,
    0x7D, 0x83, 0x85, 0x8B, 0x8D, 0x93, 0x95, 0x9B, 0x9D, 0xA3, 0xA5, 0xAA, 0xAC, 0xB2, 0xB4, 0xBC,
    0xBE, 0xC4, 0xC6, 0xCC, 0xCE, 0xD3, 0xD5, 0xD7, 0xD9, 0xDC, 0xDE, 0xE0, 0xE2, 0xE7, 0xE9, 0xEF,
    0x00, 0x01, 0x03, 0x08, 0x09, 0x0F, 0x11, 0x16, 0x18, 0x1D, 0x1F, 0x24, 0x26, 0x28, 0x2A, 0x2F,
    0x31, 0x36, 0x38, 0x39, 0x3B, 0x3D, 0x3F, 0x43, 0x45, 0x46, 0x48, 0x4F, 0x51, 0x56, 0x58, 0x5D,
    0x5F, 0x64, 0x66, 0x6B, 0x6C, 0x70, 0x72, 0x77, 0x79, 0x7C, 0x7E, 0x82, 0x84, 0x89, 0x8B, 0x92,
    0x94, 0x99, 0x9B, 0xA0, 0xA2, 0xA6, 0xA8, 0xAB, 0xAD, 0xAE, 0xB0, 0xB3, 0xB5, 0xB9, 0xB5, 0xB9,
};
extern f32 lbl_803E2390;
extern f32 gDebugGlyphCellTexels;
extern f32 lbl_803E2398;
extern f32 lbl_803E239C;
extern f32 lbl_803E23A0;
extern f32 lbl_803E23A4;
extern void GXSetTevColor(int id, int* color);
extern void setTextColor(int p);
extern u16 gDebugRectStartX;
extern u16 gDebugRectStartY;
extern u16 gDebugTabWidth;
extern u8 gDebugTextColorA;
extern u8 gDebugTextColorB;
extern u8 gDebugTextColorG;
extern u8 gDebugTextColorR;
extern u16 gDebugScreenWidth;
extern int gDebugFixedWidthMode;
extern u16* debugFrameBuffer;
extern char sErrDSI;
extern char sErrISI;
extern char sErrFmtPC;
extern char sErrFmtSP;
extern char lbl_803DBC30;
extern char lbl_803DBC34;
extern int OSDisableInterrupts(void);
extern asm BOOL OSRestoreInterrupts(register BOOL level);
extern void VISetPreRetraceCallback(void* cb);
extern void VISetPostRetraceCallback(void* cb);
extern void GXSetBreakPtCallback(void* cb);
extern void VISetNextFrameBuffer(void* fb);
extern void VIFlush(void);
extern void VIWaitForRetrace(void);
extern u16 gDebugScreenHeight;
extern u32 gDebugMarginRight;
extern u32 gDebugMarginBottom;

/* ===== EN v1.0 retargeted leaves ========================================= */

void reportAllocFail(void)
{
}

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 . */
f32 fn_80138F78(u8* obj) { return *(f32*)(*(u8**)&((GameObject*)obj)->extra + 0x14); }
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 . */
u32 fn_80138F84(u8* obj) { return *(u32*)(*(u8**)&((GameObject*)obj)->extra + 0x24); }
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 . */
s16 fn_80138F90(u8* obj) { return *(s16*)(*(u8**)&((GameObject*)obj)->extra + 0x414); }
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */
void* trickyGetQueuedPathParticlePos(u8* obj) { return &((TrickyImpressState*)((GameObject*)obj)->extra)->renderPosX; }

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */

int titlescreen_getObjectTypeId(u8* obj);

ObjectDescriptor10WithPadding gTitleScreenObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)titlescreen_initialise,
        (ObjectDescriptorCallback)titlescreen_release,
        0,
        (ObjectDescriptorCallback)titlescreen_init,
        (ObjectDescriptorCallback)titlescreen_update,
        (ObjectDescriptorCallback)titlescreen_hitDetect,
        (ObjectDescriptorCallback)titlescreen_render,
        (ObjectDescriptorCallback)titlescreen_free,
        (ObjectDescriptorCallback)titlescreen_getObjectTypeId,
        titlescreen_getExtraSize,
    },
    0,
};

/* EN v1.0 0x80139164  size: 252b  Tricky_emitQueuedPathParticles: when b->_54 carries the
 * spawn flag, build a particle descriptor on the stack from a's heading
 * and the delta to b's position, then emit it 20 times via the partfx
 * interface and clear the flag. */
#pragma peephole off
void Tricky_emitQueuedPathParticles(u8* a, u8* b)
{
    struct
    {
        s16 hx, hy, hz;
        f32 fk;
        f32 dx, dy, dz;
    } stk;
    u8 i = 0x14;
    u32 flags = ((TrickyImpressState*)b)->flags54;
    if ((flags & 0x1800) == 0) return;
    stk.dx = ((TrickyImpressState*)b)->renderPosX - ((GameObject*)a)->anim.worldPosX;
    stk.dy = ((TrickyImpressState*)b)->renderPosY - ((GameObject*)a)->anim.worldPosY;
    stk.dz = ((TrickyImpressState*)b)->renderPosZ - ((GameObject*)a)->anim.worldPosZ;
    stk.fk = lbl_803E23E8;
    stk.hx = ((GameObject*)a)->anim.rotX;
    stk.hy = ((GameObject*)a)->anim.rotY;
    stk.hz = ((GameObject*)a)->anim.rotZ;
    if ((flags & 0x800) == 0)
    {
        while (i-- != 0)
        {
            (*gPartfxInterface)->spawnObject(a, 0x533, &stk, 2, -1, NULL);
        }
        ((TrickyImpressState*)b)->flags54 = ((TrickyImpressState*)b)->flags54 & ~0x1000LL;
    }
}

#pragma optimization_level 1
int trickySelectQueuedCommandTarget(u8* state, int commandType)
{
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    u8* entry;
    int i;
    u8* bestPriorityTarget;
    u8* bestFallbackTarget;

    bestPriorityDist = lbl_803E2418;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (i = 0, entry = state; i < state[0x798]; i++)
    {
        if (*(s8*)(entry + 0x74d) == commandType)
        {
            f32 dist = getXZDistance(&((GameObject*)((TrickyState*)state)->playerObj)->anim.worldPosX,
                                     (f32*)(*(u8**)(entry + 0x748) + 0x18));

            if (*(s8*)(entry + 0x74c) == 1)
            {
                if (dist < bestPriorityDist)
                {
                    bestPriorityDist = dist;
                    bestPriorityTarget = *(u8**)(entry + 0x748);
                }
            }
            else if (dist < bestFallbackDist)
            {
                bestFallbackDist = dist;
                bestFallbackTarget = *(u8**)(entry + 0x748);
            }
        }
        entry += 8;
    }

    if (bestPriorityTarget != NULL)
    {
        ((TrickyState*)state)->followObj = bestPriorityTarget;
    }
    else
    {
        if (bestFallbackTarget == NULL)
        {
            return 0;
        }
        ((TrickyState*)state)->followObj = bestFallbackTarget;
    }

    {
        u8* targetPos = ((TrickyState*)state)->followObj + 0x18;
        if (((TrickyState*)state)->unk28 != targetPos)
        {
            ((TrickyState*)state)->unk28 = targetPos;
            *(u32*)&((TrickyState*)state)->stateFlags &= ~0x400LL;
            ((TrickyState*)state)->unkD2 = 0;
        }
    }

    state[0xa] = 0;
    return 1;
}

#pragma optimization_level reset
/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
int trickyFn_80138f14(u8* obj)
{
    u8* b = ((GameObject*)obj)->extra;
    if ((u32)GameBit_Get(0x4E4) != 0u)
    {
        ((TrickyImpressState*)b)->flags54 |= 0x10000LL;
        if ((((TrickyImpressState*)b)->flags54 & 0x10) != 0u)
        {
            return 1;
        }
    }
    return 0;
}

/* EN v1.0 0x80137998  size: 104b  Title-screen system init. Calls
 * getScreenResolution, primes the two float counters, clears two state bytes,
 * acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
#pragma peephole on
void fn_80137998(void)
{
    getScreenResolution();
    gDebugScaleX = gDebugInitialScale;
    gDebugScaleY = gDebugInitialScale;
    gDebugScaleBiasX = 0;
    gDebugScaleBiasY = 0;
    gDebugFontTex0 = textureLoadAsset(0x25D);
    gDebugFontTex1 = textureLoadAsset(1);
    gDebugFontTex2 = textureLoadAsset(2);
    debugLogEnd = debugLogBuffer;
}

/* EN v1.0 0x80137520  size: 128b  Emit a SetColor record (tag 0x81 +
 * 4 RGBA bytes + 0 terminator) into the debug log; aborts when the
 * record counter at gDebugRecordCount has already exceeded 0xFA. */
#pragma optimization_level 1
void debugPrintSetColor(u8 r, u8 g, u8 b, u8 a)
{
    int n;
    u8* p;
    u8* p2;
    u8 tag;
    u8 term;
    n = gDebugRecordCount + 1;
    gDebugRecordCount = n;
    if (n > 0xfa) return;
    tag = 0x81;
    p = debugLogEnd; debugLogEnd = p + 1; *p = tag;
    { u8* q = debugLogEnd; debugLogEnd = q + 1; *q = r; }
    { u8* q = debugLogEnd; debugLogEnd = q + 1; *q = g; }
    { u8* q = debugLogEnd; debugLogEnd = q + 1; *q = b; }
    { u8* q = debugLogEnd; debugLogEnd = q + 1; *q = a; }
    term = 0;
    p2 = debugLogEnd; debugLogEnd = p2 + 1; *p2 = term;
}
#pragma optimization_level reset

/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via objAudioFn_800393f8) only when:
 *   - bit 0x40 of obj->_b8->_58 is clear,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma peephole off
int fn_80138920(u8* obj, int sfxId, int vol)
{
    u8* b = ((GameObject*)obj)->extra;
    s16 v;
    if ((u32)((b[0x58] >> 6) & 1) != 0u) return 0;
    v = ((GameObject*)obj)->anim.currentMove;
    switch (v)
    {
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) return 0;
    objAudioFn_800393f8(obj, b + 936, sfxId, vol, -1, 0);
    return 1;
}

#pragma peephole on
void debugPrintf(char* fmt, ...)
{
    va_list args;

    if ((int)((u8*)debugLogEnd - debugLogBuffer) <= 0x1000)
    {
        va_start(args, fmt);
        vsprintf(debugLogEnd, fmt, args);
    }
}

void fn_80137948(char* fmt, ...)
{
}

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */

/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void trickyImpress(u8* obj)
{
    u8* b = ((GameObject*)obj)->extra;
    ((TrickyImpressState*)b)->flags54 |= 0x80000000;
    ((TrickyImpressState*)b)->unk808 = lbl_803E2408;
}

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */

/* EN v1.0 0x801375A0  size: 40b  Reset debug log/print state: rewind
 * debugLogEnd to the start of the buffer and reload the print x/y
 * coordinates from saved values. */
#pragma scheduling off
#pragma peephole off
void fn_801375A0(void)
{
    u32 yp;
    u32 xp;
    debugLogEnd = debugLogBuffer;
    yp = gDebugPrintOriginY & 0xffff;
    debugPrintYpos = yp;
    xp = gDebugPrintOriginX & 0xffff;
    debugPrintXpos = xp;
}

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58. */
struct Bits58 { u8 _pad[0x58]; u8 b7:1; u8 b6:1; u8 lo:6; };
void fn_80138908(u8* obj, int v)
{
    ((struct Bits58*)((GameObject*)obj)->extra)->b6 = v;
}

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &gErrDisplayThread. */
void fn_801388D0(s16 a, u32 b, u32 c, u32 d)
{
    gErrExceptionType = a;
    gErrContext = b;
    lbl_803DDA38 = c;
    lbl_803DDA34 = d;
    OSResumeThread(gErrDisplayThread);
}

void fn_80137D28(void)
{
    OSSetErrorHandler(OS_ERROR_SYSTEM_RESET, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_MACHINE_CHECK, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_DSI, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_PERFORMACE_MONITOR, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_SYSTEM_INTERRUPT, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_PROTECTION, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_ISI, fn_801388D0);
    OSSetErrorHandler(OS_ERROR_ALIGNMENT, fn_801388D0);
    OSCreateThread(gErrDisplayThread, fn_80137DF8, 0, gErrDisplayThreadStack + 4096, 4096, 0, 1);
}

int trickyFindNearestUsableBaddie(int p1, f32 maxRadius, int p2)
{
    extern int* ObjGroup_GetObjects(int, int*);
    extern int ObjGroup_ContainsObject(int, int);
    int* objs;
    int* tmpList;
    int closest;
    int i;
    f32 bestDistSq;
    int count;

    bestDistSq = maxRadius;
    closest = 0;
    tmpList = ObjGroup_GetObjects(3, &count);
    bestDistSq = bestDistSq * bestDistSq;
    i = 0;
    objs = tmpList;

    for (; i < count; i++)
    {
        int* data;
        f32 obj_extra;
        int v1, v2;
        s32 g1, g2;

        if (dll_19_func1B(*objs) != 0)
        {
            obj_extra = (**(f32 (**)(int))((char*)(*gBaddieControlInterface) + 0x60))(*objs);
        }
        else
        {
            obj_extra = fn_8014C5D0(*objs);
        }

        data = (int*)*(int*)(*objs + 0x4c);
        g1 = *(s16*)((char*)data + 0x18);
        if (g1 == -1)
        {
            v1 = 0;
        }
        else
        {
            v1 = GameBit_Get(g1);
        }
        g2 = *(s16*)((char*)data + 0x1a);
        if (g2 == -1)
        {
            v2 = 1;
        }
        else
        {
            v2 = GameBit_Get(g2);
        }

        if (ObjGroup_ContainsObject(*objs, 49) == 0 &&
            obj_extra > lbl_803E23DC &&
            v1 == 0 &&
            v2 != 0)
        {
            if (((GameObject*)*objs)->anim.seqId != 2129)
            {
                if ((*gMapEventInterface)->shouldNotSaveTime(
                    *(int*)((char*)data + 0x14)) != 0)
                {
                    if (p2 == 0)
                    {
                        s16 m = ((GameObject*)*objs)->anim.seqId;
                        if (m == 1022 || m == 1239 || m == 636 || m == 593) goto next;
                    }
                    {
                        f32 dist = vec3f_distanceSquared(p1 + 0x18, *objs + 0x18);
                        if (dist < bestDistSq)
                        {
                            bestDistSq = dist;
                            closest = *objs;
                        }
                    }
                }
            }
        }
    next:
        objs++;
    }
    return closest;
}

#pragma peephole off
void fn_80138D7C(int obj, int p2)
{
    u8 ratio = (u8)((s32) * (u8*)(*(int*)(p2 + 0) + 2) / 10);

    if (*(u8*)(p2 + 0x82c) != ratio)
    {
        f32 t;
        if (GameBit_Get(1005) == 0)
        {
            GameBit_Set(1005, 1);
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
            ((TrickyImpressState*)p2)->flags54 |= 0x4000;
            *(f32*)(p2 + 0x828) = *(f32*)(p2 + 0x828) + lbl_803E2408;
        }
        *(f32*)(p2 + 0x828) = *(f32*)(p2 + 0x828) - timeDelta;
        t = *(f32*)(p2 + 0x828);
        if (!(t > lbl_803E2408))
        {
            if (t > lbl_803E23DC)
            {
                f32 alpha;
                if (t > lbl_803E23E0)
                {
                    alpha = lbl_803E23E8 - (t - lbl_803E23E0) / lbl_803E23E0;
                }
                else
                {
                    *(u8*)(*(int*)((char*)Obj_GetActiveModel(obj) + 0x34) + 8) = ratio;
                    alpha = *(f32*)(p2 + 0x828) / lbl_803E23E0;
                }
                Obj_SetModelColorOverrideRecursive(obj, 255, 255, 255, (s32)(lbl_803E240C * alpha), 1);
            }
            else
            {
                *(u8*)(p2 + 0x82c) = ratio;
                Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
            }
        }
    }
}

#define TUMBLEWEED_BLEND_FLAGS_OFFSET 0x82e
#define TUMBLEWEED_BLEND_WEIGHT_OFFSET 0x830
#define TUMBLEWEED_BLEND_VELOCITY_OFFSET 0x834

typedef struct {
    u8 pending : 1;
    u8 active : 1;
    u8 rest : 6;
} TumbleweedBlendFlags;

/* Tricky_updateBlendChannelWeight: weighted blend-channel animator. On state[0x82e] bit 0x80,
 * primes channel 1 (weight 0, target weight ratio at +0x830) and latches
 * the active flag. While bit 0x40 is set, ramps state[0x830] toward
 * data[0] / data[1] with acceleration lbl_803E23E4 and damping
 * lbl_803E23F0, clamps to [0, lbl_803E23E8], and pushes the result to the
 * model's blend channel 1 as `lbl_803E23F8 * weight - lbl_803E23E8`. */
void Tricky_updateBlendChannelWeight(int obj, u8* state)
{
    int model;
    f32 target;
    Obj_GetActiveModel(obj);
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 7) & 1) != 0)
    {
        model = (int)Obj_GetActiveModel(obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, lbl_803E23DC, 0x21);
        *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E0;
        ObjModel_SetBlendChannelWeight(model, 0, lbl_803E23DC);
        ((TumbleweedBlendFlags*)(state + TUMBLEWEED_BLEND_FLAGS_OFFSET))->pending = 0;
        ((TumbleweedBlendFlags*)(state + TUMBLEWEED_BLEND_FLAGS_OFFSET))->active = 1;
    }
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 6) & 1) != 0)
    {
        u8* data = *(u8**)(state + 0);
        target = (f32)(u32)
        data[0] / (f32)(u32)
        data[1];
        if (target > *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET))
        {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                lbl_803E23E4 * timeDelta + *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET);
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > lbl_803E23E8)
            {
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E8;
            }
            else if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > target)
            {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) < lbl_803E23EC)
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                }
                else
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        }
        else if (target < *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET))
        {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) - lbl_803E23E4 * timeDelta;
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < *(f32*)&lbl_803E23DC)
            {
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
            }
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < target)
            {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) > lbl_803E23F4)
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                }
                else
                {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(
            (int)Obj_GetActiveModel(obj), 1,
            lbl_803E23F8 * *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) - lbl_803E23E8);
    }
}

PPCWGPipe GXWGFifo : (0xCC008000);

typedef struct
{
    u8 s0 : 2;
    u8 s1 : 2;
    u8 s2 : 2;
    u8 s3 : 2;
} AnimSlots;

void objAnimFreeChildren(int a, int b, void** c)
{
    char buf[4];
    void *v0, *v1, *v2;

    if (*c == NULL)
    {
        return;
    }
    ObjLink_DetachChild(a, (int)*c);
    Obj_FreeObject(*c);
    *c = NULL;
    buf[0] = -1;
    buf[1] = -1;
    buf[2] = -1;
    v0 = *(void**)(b + 0x7a8);
    if (v0 != NULL)
    {
        buf[((TrickyImpressState*)b)->childSlotMap >> 6 & 3] = 1;
    }
    v1 = *(void**)(b + 0x7b0);
    if (v1 != NULL)
    {
        buf[((TrickyImpressState*)b)->childSlotMap >> 4 & 3] = 1;
    }
    v2 = *(void**)(b + 0x7b8);
    if (v2 != NULL)
    {
        buf[((TrickyImpressState*)b)->childSlotMap >> 2 & 3] = 1;
    }
    if (buf[0] == -1)
    {
        if (v0 != NULL)
        {
            ObjLink_DetachChild(a, v0);
            ObjLink_AttachChild(a, ((TrickyImpressState*)b)->childObj0, 0);
            ((AnimSlots*)(b + 0x7bc))->s0 = 0;
        }
        else if (v1 != NULL)
        {
            ObjLink_DetachChild(a, v1);
            ObjLink_AttachChild(a, ((TrickyImpressState*)b)->childObj1, 0);
            ((AnimSlots*)(b + 0x7bc))->s1 = 0;
        }
        else if (v2 != NULL)
        {
            ObjLink_DetachChild(a, v2);
            ObjLink_AttachChild(a, ((TrickyImpressState*)b)->childObj2, 0);
            ((AnimSlots*)(b + 0x7bc))->s2 = 0;
        }
    }
}

#pragma opt_strength_reduction off
void fn_80137A00(int x, int y, u8* grid, int unused)
{
    int c1;
    int i;
    int a0;
    int a1;
    int a2;
    int a3;
    int c0;
    int bit;
    int row1;
    int row0;

    if (enableDebugText != 0)
    {
        i = 0;
        row1 = (y + 1) * 0x280;
        row0 = y * 0x280;
        for (; i < 5; i++)
        {
            bit = 0;
            c0 = row0 + x;
            a0 = c0;
            a1 = c0 + 1;
            c1 = row1 + x;
            a2 = c1;
            a3 = c1 + 1;
            for (; bit < 8; bit++)
            {
                if (((1 << bit) & grid[i]) != 0)
                {
                    debugDrawFrameBuffer[a0] = 0xC080;
                    debugDrawFrameBuffer[a1] = 0xC080;
                    debugDrawFrameBuffer[a2] = 0xC080;
                    debugDrawFrameBuffer[a3] = 0xC080;
                }
                a0++;
                a1++;
                a2++;
                a3++;
            }
            DCStoreRange((char*)debugDrawFrameBuffer + c0 * 2, 0x10);
            DCStoreRange((char*)debugDrawFrameBuffer + c1 * 2, 0x10);
            row0 += 0x500;
            row1 += 0x500;
        }
    }
}
#pragma opt_strength_reduction reset

void debugPrintfxy(int x, int y, char* fmt, ...)
{
    int xx;
    int yy;
    u16* saved;
    int x0 = x;
    u8* ch;
    u8* scan;
    u8* glyph;
    va_list args;
    char buf[256];

    if (enableDebugText != 0)
    {
        xx = x0;
        yy = y;
        va_start(args, fmt);
        vsprintf(buf, fmt, args);
        saved = debugDrawFrameBuffer;
        ch = (u8*)&buf[-1];
        scan = (u8*)buf - 1;
        while (ch++, *++scan != 0)
        {
            switch (*ch)
            {
            case 0xa:
                yy += 0xc;
                xx = x0;
                break;
            case 9:
                xx += 0x40 - (xx & 0x3f);
                break;
            case 0x20:
                xx += 8;
                break;
            default:
                if (*ch >= 0x61 && *ch <= 0x7a)
                {
                    *ch -= 0x20;
                }
                if (*ch >= 0x21 && *ch <= 0x5a)
                {
                    debugDrawFrameBuffer = externalFrameBuffer0;
                    fn_80137A00(xx, yy, glyph = gDebugFontGlyphs + (*ch - 0x21) * 5, -1);
                    debugDrawFrameBuffer = externalFrameBuffer1;
                    fn_80137A00(xx, yy, glyph, -1);
                    xx += 0xf;
                }
                break;
            }
        }
        debugDrawFrameBuffer = saved;
    }
}

int fn_80136A40(int p1, int c)
{
    u8* tbl;
    u8 first;
    int px;
    int py;

    if (c <= 0x3f)
    {
        if (gDebugCurrentFontSet != 0)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((char*)gDebugFontTex0, 0);
                gDebugGlyphUScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex0 + 10));
                gDebugGlyphVScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex0 + 0xc));
            }
            gDebugCurrentFontSet = 0;
        }
        c -= 0x21;
    }
    else if (c <= 0x5f)
    {
        if (gDebugCurrentFontSet != 1)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((char*)gDebugFontTex1, 0);
                gDebugGlyphUScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex1 + 10));
                gDebugGlyphVScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex1 + 0xc));
            }
            gDebugCurrentFontSet = 1;
        }
        c -= 0x40;
    }
    else if (c <= 0x7f)
    {
        if (gDebugCurrentFontSet != 2)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((char*)gDebugFontTex2, 0);
                gDebugGlyphUScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex2 + 10));
                gDebugGlyphVScale = lbl_803E2390 / (gDebugGlyphCellTexels * (f32) * (u16*)((char*)gDebugFontTex2 + 0xc));
            }
            gDebugCurrentFontSet = 2;
        }
        c -= 0x60;
    }
    tbl = gDebugGlyphMetricsTable + gDebugCurrentFontSet * 0x40;
    first = tbl[c * 2];
    c = tbl[c * 2 + 1] - first + 1;
    if (gDebugDrawPass != 0)
    {
        px = (int)((f32)debugPrintYpos * (gDebugScaleX + gDebugScaleBiasX));
        py = (int)((f32)debugPrintXpos * (gDebugScaleY + gDebugScaleBiasY));
        gxDebugTextureFn_80078c1c();
        textRenderChar(px << 2, py << 2,
                       (int)(*(f32*)&lbl_803E2398 * ((f32)c * (gDebugScaleX + gDebugScaleBiasX) + px)),
                       (int)(lbl_803E2398 * (lbl_803E239C * (gDebugScaleY + gDebugScaleBiasY) + py)),
                       (f32)(first << 5) * gDebugGlyphUScale,
                       lbl_803E23A0,
                       gDebugGlyphUScale * (f32)((first + c) << 5),
                       lbl_803E23A4 * gDebugGlyphVScale);
    }
    return c;
}

#pragma peephole off
#pragma optimization_level 3
int fn_80136E00(int p1, u8* p)
{
    u8 c;
    int w;
    int x2;
    int y;
    int y0;
    int y1;
    u16 x0;
    u32 ca;
    u32 cb;
    u32 cc;
    u32 cd;
    f32 sc;
    int rm;
    u8 c0;
    u8 c1;
    u8 c2;
    u8 c3;
    u8 colb1[4];
    u32 colw1;
    u32 colw4; /* case 0x82 */
    u8 colb4[4];
    u32 colw2; /* case 0xa */
    u8 colb2[4];
    u32 colw3; /* line-wrap path */
    u8 colb3[4];
    u8* start = p;

    while ((c = *p++) != 0)
    {
        w = 0;
        switch (c)
        {
        case 0x83:
            gDebugFixedWidthMode = 0;
            break;
        case 0x84:
            gDebugFixedWidthMode = 1;
            break;
        case 0x81:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (gDebugDrawPass != 0)
            {
                colb1[0] = c0;
                colb1[1] = c1;
                colb1[2] = c2;
                colb1[3] = c3;
                colw1 = *(u32*)colb1;
                GXSetTevColor(1, (int*)&colw1);
            }
            break;
        case 0x87:
            gDebugScaleBiasX = p[0];
            c0 = p[1];
            p += 2;
            gDebugScaleBiasY = c0;
            break;
        case 0x85:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (gDebugDrawPass == 0)
            {
                gDebugTextColorR = c0;
                gDebugTextColorG = c1;
                gDebugTextColorB = c2;
                gDebugTextColorA = c3;
                setTextColor(p1);
            }
            break;
        case 0x82:
            if (gDebugDrawPass == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = gDebugRectStartX;
                y0 = gDebugRectStartY;
                if ((((y - y0) == 0) | ((x2 - x0) == 0)) == 0)
                {
                    if ((u32)y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    ca = (u32)((f32)(u32)y0 * (sc = gDebugScaleX + gDebugScaleBiasX));
                    cb = (u32)((f32)(u32)y1 * sc);
                    cc = (u32)((f32)x0 * (sc = gDebugScaleY + gDebugScaleBiasY));
                    cd = (u32)((f32)(u32)x2 * sc);
                    colb4[0] = gDebugTextColorR;
                    colb4[1] = gDebugTextColorG;
                    colb4[2] = gDebugTextColorB;
                    colb4[3] = gDebugTextColorA;
                    colw4 = *(u32*)colb4;
                    hudDrawRect(ca, cc, cb, cd, &colw4);
                }
            }
            debugPrintYpos = p[0];
            debugPrintYpos = (u16)debugPrintYpos | (p[1] << 8);
            debugPrintXpos = p[2];
            c0 = p[3];
            p += 4;
            debugPrintXpos |= c0 << 8;
            gDebugRectStartY = debugPrintYpos;
            gDebugRectStartX = debugPrintXpos;
            break;
        case 0x86:
            gDebugTabWidth = p[0];
            c0 = p[1];
            p += 2;
            gDebugTabWidth |= c0 << 8;
            break;
        case 0x20:
            w = 6;
            break;
        case 0xa:
            if (gDebugDrawPass == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = gDebugRectStartX;
                y0 = gDebugRectStartY;
                if ((((y - y0) == 0) | ((x2 - x0) == 0)) == 0)
                {
                    if ((u32)y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    ca = (u32)((f32)(u32)y0 * (sc = gDebugScaleX + gDebugScaleBiasX));
                    cb = (u32)((f32)(u32)y1 * sc);
                    cc = (u32)((f32)x0 * (sc = gDebugScaleY + gDebugScaleBiasY));
                    cd = (u32)((f32)(u32)x2 * sc);
                    colb2[0] = gDebugTextColorR;
                    colb2[1] = gDebugTextColorG;
                    colb2[2] = gDebugTextColorB;
                    colb2[3] = gDebugTextColorA;
                    colw2 = *(u32*)colb2;
                    hudDrawRect(ca, cc, cb, cd, &colw2);
                }
            }
            debugPrintYpos = gDebugPrintOriginY;
            debugPrintXpos += 0xb;
            gDebugRectStartY = debugPrintYpos;
            gDebugRectStartX = debugPrintXpos;
            break;
        case 9:
            rm = debugPrintYpos % gDebugTabWidth;
            if (rm == 0)
            {
                w = gDebugTabWidth;
            }
            else
            {
                w = gDebugTabWidth - rm;
            }
            break;
        default:
            w = fn_80136A40(p1, c);
            break;
        }
        if (gDebugFixedWidthMode != 0 && c >= 0x20 && c <= 0x7f)
        {
            w = 7;
        }
        debugPrintYpos += w;
        if ((f32)debugPrintYpos * (sc = gDebugScaleX + gDebugScaleBiasX) >
            (f32)(int)(gDebugScreenWidth - 0x10))
        {
            if (gDebugDrawPass == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = gDebugRectStartX;
                y0 = gDebugRectStartY;
                if ((((y - y0) == 0) | ((x2 - x0) == 0)) == 0)
                {
                    if ((u32)y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    ca = (u32)((f32)(u32)y0 * sc);
                    cb = (u32)((f32)(u32)y1 * sc);
                    cc = (u32)((f32)x0 * (sc = gDebugScaleY + gDebugScaleBiasY));
                    cd = (u32)((f32)(u32)x2 * sc);
                    colb3[0] = gDebugTextColorR;
                    colb3[1] = gDebugTextColorG;
                    colb3[2] = gDebugTextColorB;
                    colb3[3] = gDebugTextColorA;
                    colw3 = *(u32*)colb3;
                    hudDrawRect(ca, cc, cb, cd, &colw3);
                }
            }
            debugPrintYpos = gDebugPrintOriginY;
            debugPrintXpos += 0xb;
            gDebugRectStartY = debugPrintYpos;
            gDebugRectStartX = debugPrintXpos;
        }
    }
    return p - start;
}
#pragma optimization_level reset

/* EN v1.0 0x80137DF8  size: 2776b  fn_80137DF8: error display thread.
 * Clears the debug framebuffer, prints the exception type, DSISR/SRR0,
 * stack trace and GPR dump via debugPrintfxy, draws the underline and
 * box pixels directly into the framebuffer, and flips buffers forever. */
#pragma ppc_unroll_speculative on
#pragma opt_strength_reduction off
#pragma opt_propagation off
void fn_80137DF8(void)
{
    char* strs = (char*)gDebugFontGlyphs;
    void (*self)(void);
    int y;
    u32* sp;
    int depth;
    int hold;
    int x, col;
    int row;
    u16* fbrow;
    int h, h2;
    int b;
    int n;
    u32 cnt;
    u32* p;
    u8 lvl;
    u32 r, rr;
    int rp;
    int rows;
    u16 fill;

    sp = NULL;
    depth = 0;
    hold = 0xb4;
    if (enableDebugText != 0)
    {
        debugDrawFrameBuffer = externalFrameBuffer0;
        debugFrameBuffer = externalFrameBuffer1;
        lvl = OSDisableInterrupts();
        VISetPreRetraceCallback(NULL);
        VISetPostRetraceCallback(NULL);
        GXSetBreakPtCallback(NULL);
        __GXAbortWaitPECopyDone();
        OSRestoreInterrupts(lvl);
        self = fn_80137DF8;
        while (1)
        {
            if (enableDebugText != 0)
            {
                x = 0;
                col = x;
                for (; x < 0x280; x++)
                {
                    row = 0;
                    for (n = 0; n < 60; n++)
                    {
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + row);
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x500));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0xA00));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0xF00));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1400));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1900));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1E00));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x2300));
                        *(u16*)((char*)fbrow + col) = 0x1080;
                        row += 0x2800;
                    }
                    col += 2;
                }
            }
            debugPrintfxy(0x10, 0x15, strs + 0x140, self);
            debugPrintfxy(0x10, 0x2a, strs + 0x154);
            switch (*(u16*)&gErrExceptionType)
            {
            case 0:
                debugPrintfxy(0xa0, 0x2a, strs + 0x160);
                break;
            case 1:
                debugPrintfxy(0xa0, 0x2a, strs + 0x170);
                break;
            case 2:
                debugPrintfxy(0xa0, 0x2a, &sErrDSI);
                break;
            case 3:
                debugPrintfxy(0xa0, 0x2a, &sErrISI);
                break;
            case 5:
                debugPrintfxy(0xa0, 0x2a, strs + 0x180);
                break;
            case 0xb:
                debugPrintfxy(0x9b, 0x2a, strs + 0x18c);
                break;
            case 0xd:
                debugPrintfxy(0xa0, 0x2a, strs + 0x1a0);
                break;
            case 0xf:
                debugPrintfxy(0xa0, 0x2a, strs + 0x1bc);
                break;
            default:
                debugPrintfxy(0x9b, 0x2a, strs + 0x1d4);
                break;
            }
            if (enableDebugText != 0)
            {
                h = 0x9100;
                h2 = 0x8e80;
                for (n = 0x280; n != 0; n--)
                {
                    debugDrawFrameBuffer[h] = 0xc080;
                    debugDrawFrameBuffer[h2] = 0xc080;
                    h++;
                    h2++;
                }
            }
            debugPrintfxy(0x10, 0x3f, &sErrFmtPC, *(u32*)(gErrContext + 0x198));
            debugPrintfxy(0x10, 0x4b, &sErrFmtSP, *(u32*)(gErrContext + 4));
            if (enableDebugText != 0)
            {
                h = 0xe380;
                h2 = 0xe100;
                for (n = 0xf0; n != 0; n--)
                {
                    debugDrawFrameBuffer[h] = 0xc080;
                    debugDrawFrameBuffer[h2] = 0xc080;
                    h++;
                    h2++;
                }
            }
            debugPrintfxy(0x10, 0x60, strs + 0x1e4);
            y = 0x6c;
            p = (u32*)**(u32**)(gErrContext + 4);
            n = 0;
            while (p != (u32*)0xffffffff && n++ != 8)
            {
                debugPrintfxy(0x10, y, &lbl_803DBC30, p[1]);
                y += 0xc;
                p = (u32*)*p;
            }
            y += (8 - n) * 0xc;
            if (enableDebugText != 0)
            {
                rows = y + 0x4c;
                h = rows * 0x280;
                h2 = (y + 0x4b) * 0x280;
                fill = 0xc080;
                if (rows > 0)
                {
                    for (n = 0x280; n != 0; n--)
                    {
                        debugDrawFrameBuffer[h] = fill;
                        debugDrawFrameBuffer[h2] = fill;
                        h++;
                        h2++;
                    }
                }
                else
                {
                    for (n = 0x280; n != 0; n--)
                    {
                        debugDrawFrameBuffer[h] = fill;
                        h++;
                    }
                }
            }
            if (enableDebugText != 0)
            {
                b = 0x12700;
                rows = y + 0x4c;
                if (rows > 0x3b)
                {
                    for (cnt = rows - 0x3b; cnt != 0; cnt--)
                    {
                        *(u16*)((char*)debugDrawFrameBuffer + b + 0x1e0) = 0xc080;
                        b += 0x500;
                    }
                }
            }
            y += 0x51;
            if (sp == NULL)
            {
                sp = *(u32**)(gErrContext + 4);
                depth = 0;
            }
            else if (hold-- == 0)
            {
                hold = 0xb4;
                sp = (u32*)*sp;
                depth++;
                if (sp == (u32*)0xffffffff)
                {
                    sp = *(u32**)(gErrContext + 4);
                    depth = 0;
                }
            }
            debugPrintfxy(0x100, 0x3f, strs + 0x1f0, sp, depth);
            debugPrintfxy(0x100, 0x4b, strs + 0x204, sp[-1], sp[-2]);
            debugPrintfxy(0x100, 0x57, strs + 0x204, sp[-3], sp[-4]);
            debugPrintfxy(0x100, 0x63, strs + 0x204, sp[-5], sp[-6]);
            debugPrintfxy(0x100, 0x6f, strs + 0x204, sp[-7], sp[-8]);
            debugPrintfxy(0x100, 0x7b, strs + 0x204, sp[-9], sp[-10]);
            debugPrintfxy(0x100, 0x87, strs + 0x204, sp[-0xb], sp[-0xc]);
            debugPrintfxy(0x100, 0x93, strs + 0x204, sp[-0xd], sp[-0xe]);
            debugPrintfxy(0x100, 0x9f, strs + 0x204, sp[-0xf], sp[-0x10]);
            debugPrintfxy(0x100, 0xab, strs + 0x204, sp[-0x11], sp[-0x12]);
            debugPrintfxy(0x100, 0xb7, strs + 0x204, sp[-0x13], sp[-0x14]);
            debugPrintfxy(0x100, 0xc3, strs + 0x204, sp[-0x15], sp[-0x16]);
            debugPrintfxy(0x100, 0xcf, strs + 0x204, sp[-0x17], sp[-0x18]);
            debugPrintfxy(0x100, 0xdb, strs + 0x204, sp[-0x19], sp[-0x1a]);
            debugPrintfxy(0x100, 0xe7, strs + 0x204, sp[-0x1b], sp[-0x1c]);
            debugPrintfxy(0x100, 0xf3, strs + 0x204, sp[-0x1d], sp[-0x1e]);
            debugPrintfxy(0x100, 0xff, strs + 0x204, sp[-0x1f], sp[-0x20]);
            debugPrintfxy(0x10, y, strs + 0x210);
            for (r = 0; (r & 0xff) < 0x20; r += 8)
            {
                rr = r & 0xff;
                debugPrintfxy(0xc, y + 0xc, &lbl_803DBC34, rr, rr + 7);
                rp = gErrContext + rr * 4;
                debugPrintfxy(0x10, y + 0x18, strs + 0x22c,
                              *(u32*)(gErrContext + (r & 0xff) * 4), *(u32*)(rp + 4),
                              *(u32*)(rp + 8), *(u32*)(rp + 0xc));
                y += 0x24;
                rp = gErrContext + rr * 4;
                debugPrintfxy(0x10, y, strs + 0x22c, *(u32*)(rp + 0x10),
                              *(u32*)(rp + 0x14), *(u32*)(rp + 0x18), *(u32*)(rp + 0x1c));
            }
            if (enableDebugText != 0)
            {
                DCStoreRange(debugDrawFrameBuffer, 0x96000);
                debugDrawFrameBuffer = (debugDrawFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
                debugFrameBuffer = (debugFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
                VISetNextFrameBuffer(debugFrameBuffer);
                VIFlush();
                VIWaitForRetrace();
            }
        }
    }
    while (1)
    {
        if (enableDebugText != 0)
        {
            x = 0;
            col = x;
            for (; x < 0x280; x++)
            {
                row = 0;
                for (n = 0; n < 60; n++)
                {
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + row);
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x500));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0xA00));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0xF00));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1400));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1900));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x1E00));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    fbrow = (u16*)((char*)debugDrawFrameBuffer + (row + 0x2300));
                    *(u16*)((char*)fbrow + col) = 0x1080;
                    row += 0x2800;
                }
                col += 2;
            }
        }
        if (enableDebugText != 0)
        {
            DCStoreRange(debugDrawFrameBuffer, 0x96000);
            debugDrawFrameBuffer = (debugDrawFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
            debugFrameBuffer = (debugFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
            VISetNextFrameBuffer(debugFrameBuffer);
            VIFlush();
            VIWaitForRetrace();
        }
    }
}
#pragma opt_propagation off
#pragma opt_strength_reduction on
#pragma ppc_unroll_speculative on

/* EN v1.0 0x801375C8  size: 736b  debugPrintDraw: lay out the debug log
 * twice (measure pass then draw pass), drawing the backing rect between
 * the passes when the log produced any extent. */
void debugPrintDraw(int ctx)
{
    u32 ys;
    u32 y2;
    u32 xa, xb, ya, yb;
    u32 xs;
    u32 colw;
    u8* p;
    u16 tx, ty;
    u32 colb;
    u32 x1;
    f32 scale;
    int pass;
    u32 res;
    u32 sw;
    u32 yv;
    u32 sh;

    res = getScreenResolution();
    gDebugScreenHeight = res >> 0x10;
    gDebugScreenWidth = res;
    GXSetScissor(0, 0, (u16)res, gDebugScreenHeight);
    sw = gDebugScreenWidth;
    if (sw <= 0x140)
    {
        gDebugPrintOriginY = 0x10;
        gDebugMarginRight = sw - 0x10;
    }
    else
    {
        gDebugPrintOriginY = 0x20;
        gDebugMarginRight = sw - 0x20;
    }
    sh = gDebugScreenHeight;
    if (sh <= 0xf0)
    {
        gDebugPrintOriginX = 0x10;
        gDebugMarginBottom = sh - 0x10;
    }
    else
    {
        gDebugPrintOriginX = 0x20;
        gDebugMarginBottom = sh - 0x20;
    }
    gxDebugTextureFn_80078c1c();
    p = debugLogBuffer;
    debugPrintYpos = ty = gDebugPrintOriginY;
    debugPrintXpos = tx = gDebugPrintOriginX;
    gDebugCurrentFontSet = 0xffffffff;
    pass = 0;
    gDebugFixedWidthMode = pass;
    gDebugRectStartY = ty;
    gDebugRectStartX = tx;
    for (; p != debugLogEnd;)
    {
        gDebugDrawPass = pass;
        p += fn_80136E00(ctx, p);
    }
    x1 = debugPrintXpos + 0xa;
    yv = debugPrintYpos;
    xs = gDebugRectStartX;
    ys = gDebugRectStartY;
    if ((((yv - ys) == 0) | ((x1 - xs) == 0)) == 0)
    {
        if (ys >= 2)
        {
            ys -= 2;
        }
        y2 = yv + 2;
        xa = (u32)((f32)ys * (scale = gDebugScaleX + gDebugScaleBiasX));
        xb = (u32)((f32)y2 * scale);
        ya = (u32)((f32)xs * (scale = gDebugScaleY + gDebugScaleBiasY));
        yb = (u32)((f32)x1 * scale);
        ((u8*)&colb)[0] = gDebugTextColorR;
        ((u8*)&colb)[1] = gDebugTextColorG;
        ((u8*)&colb)[2] = gDebugTextColorB;
        ((u8*)&colb)[3] = gDebugTextColorA;
        colw = colb;
        hudDrawRect(xa, ya, xb, yb, &colw);
    }
    p = debugLogBuffer;
    debugPrintYpos = gDebugPrintOriginY;
    debugPrintXpos = gDebugPrintOriginX;
    gDebugCurrentFontSet = 0xffffffff;
    gDebugFixedWidthMode = 0;
    pass = 1;
    for (; p != debugLogEnd;)
    {
        gDebugDrawPass = pass;
        p += fn_80136E00(ctx, p);
    }
    debugLogEnd = debugLogBuffer;
    gDebugRecordCount = 0;
}

u8 gDebugFontGlyphs[580] = {
    12, 12, 12, 0, 12, 51, 51, 0, 0, 0, 38, 63, 38, 63, 38, 44,
    14, 46, 44, 14, 51, 40, 29, 10, 51, 29, 51, 45, 51, 62, 12, 12,
    0, 0, 0, 14, 3, 3, 3, 14, 28, 48, 48, 48, 28, 0, 12, 63,
    29, 55, 0, 12, 63, 12, 0, 0, 0, 0, 13, 3, 0, 0, 63, 0,
    0, 0, 0, 0, 0, 12, 48, 56, 25, 11, 3, 30, 41, 45, 37, 30,
    12, 15, 12, 12, 63, 31, 48, 30, 3, 63, 31, 48, 62, 48, 31, 24,
    28, 18, 63, 16, 63, 3, 31, 48, 31, 30, 3, 31, 51, 30, 63, 48,
    24, 12, 12, 30, 51, 30, 51, 30, 30, 51, 62, 48, 30, 0, 3, 0,
    3, 0, 0, 12, 0, 12, 2, 56, 14, 3, 14, 56, 0, 63, 0, 63,
    0, 7, 28, 48, 28, 7, 30, 51, 24, 0, 12, 60, 129, 189, 161, 28,
    30, 51, 63, 51, 51, 31, 51, 31, 51, 31, 30, 51, 3, 51, 30, 31,
    51, 51, 51, 31, 63, 3, 31, 3, 63, 63, 3, 31, 3, 3, 62, 3,
    59, 51, 30, 51, 51, 63, 51, 51, 63, 12, 12, 12, 63, 63, 48, 51,
    51, 46, 51, 51, 31, 51, 51, 3, 3, 3, 3, 63, 51, 63, 45, 33,
    33, 51, 55, 63, 59, 51, 30, 51, 51, 51, 30, 31, 51, 31, 3, 3,
    46, 51, 51, 55, 62, 31, 51, 31, 51, 51, 62, 3, 30, 48, 31, 63,
    12, 12, 12, 12, 51, 51, 51, 51, 30, 51, 51, 51, 26, 12, 33, 33,
    45, 63, 51, 51, 51, 30, 51, 51, 51, 51, 30, 12, 12, 63, 24, 30,
    6, 63, 63, 3, 3, 3, 63, 6, 12, 24, 48, 63, 48, 48, 48, 63,
    12, 51, 0, 0, 0, 0, 0, 0, 0, 63, 3, 12, 0, 0, 0, 0,
    9, 101, 114, 114, 111, 114, 84, 104, 114, 101, 97, 100, 70, 117, 110, 99,
    32, 37, 120, 0, 69, 120, 99, 101, 112, 116, 105, 111, 110, 58, 0, 0,
    83, 121, 115, 116, 101, 109, 32, 114, 101, 115, 101, 116, 0, 0, 0, 0,
    77, 97, 99, 104, 105, 110, 101, 32, 99, 104, 101, 99, 107, 0, 0, 0,
    65, 108, 105, 103, 110, 109, 101, 110, 116, 0, 0, 0, 80, 101, 114, 102,
    111, 114, 109, 97, 110, 99, 101, 32, 109, 111, 110, 105, 116, 111, 114, 0,
    83, 121, 115, 116, 101, 109, 32, 109, 97, 110, 97, 103, 101, 109, 101, 110,
    116, 32, 105, 110, 116, 101, 114, 114, 117, 112, 116, 0, 77, 101, 109, 111,
    114, 121, 32, 80, 114, 111, 116, 101, 99, 116, 105, 111, 110, 32, 69, 114,
    114, 111, 114, 0, 85, 110, 107, 110, 111, 119, 110, 32, 101, 114, 114, 111,
    114, 0, 0, 0, 83, 116, 97, 99, 107, 32, 116, 114, 97, 99, 101, 0,
    83, 116, 97, 99, 107, 32, 37, 120, 59, 32, 100, 101, 112, 116, 104, 32,
    37, 100, 0, 0, 9, 37, 48, 56, 120, 9, 37, 48, 56, 120, 0, 0,
    71, 101, 110, 101, 114, 97, 108, 32, 80, 117, 114, 112, 111, 115, 101, 32,
    82, 101, 103, 105, 115, 116, 101, 114, 115, 0, 0, 0, 9, 37, 48, 56,
    120, 9, 37, 48, 56, 120, 9, 37, 48, 56, 120, 9, 37, 48, 56, 120,
    0, 0, 0, 0,
};
