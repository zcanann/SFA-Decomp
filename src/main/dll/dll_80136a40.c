#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "stdarg.h"

typedef struct TrickyImpressState
{
    u8 pad0[0x54 - 0x0];
    u32 unk54;
    u8 pad58[0x408 - 0x58];
    f32 unk408;
    f32 unk40C;
    f32 unk410;
    u8 pad414[0x7A8 - 0x414];
    s32 unk7A8;
    u8 pad7AC[0x7B0 - 0x7AC];
    s32 unk7B0;
    u8 pad7B4[0x7B8 - 0x7B4];
    s32 unk7B8;
    u8 unk7BC;
    u8 pad7BD[0x808 - 0x7BD];
    f32 unk808;
    u8 pad80C[0x810 - 0x80C];
} TrickyImpressState;

extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined8 FUN_80053754();
extern undefined4 FUN_80246dcc();

extern undefined4 DAT_803dc818;
extern undefined4 DAT_803de5a8;
extern undefined4 DAT_803de5c4;
extern undefined4 DAT_803de62b;
extern undefined4 DAT_803de6b4;
extern undefined4 DAT_803de6b8;
extern undefined4 DAT_803de6bc;
extern undefined4 DAT_803de6c0;
extern f32 FLOAT_803e3098;

extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern void GXSetScissor(int x, int y, int w, int h);
extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32* color);

extern u8 lbl_803DBBB0;
extern u8 lbl_803DD928;
extern void* minimapTexture;
extern void* lbl_803DD940;
extern s8 lbl_803DD944;

#pragma scheduling on
#pragma peephole on
extern u8 warpstoneUIState;
extern u8 showCredits;
extern void titlescreen_free(u8 * obj);
extern void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void titlescreen_update(u8 * obj);
extern void titlescreen_init(u8 * obj, u8 * p);
extern void titlescreen_release(void);
extern void titlescreen_initialise(void);
extern f32 lbl_803DD968;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2344;
extern void* lbl_803DBBC8[2];
extern void Obj_FreeObject(void*);
extern f32 lbl_803E23B8;
extern f32 lbl_803DD9D8;
extern f32 lbl_803DD9DC;
extern u8 lbl_803DD9E0;
extern u8 lbl_803DD9E1;
extern void* lbl_803DDA1C;
extern void* lbl_803DDA20;
extern void* lbl_803DDA24;
extern void* debugLogEnd;
extern u8 debugLogBuffer[0x1100];
extern u32 getScreenResolution(void);
extern int vsprintf(char* s, const char* format, va_list arg);
extern int lbl_803DD9E4;
extern int Sfx_IsPlayingFromObjectChannel(u8*, int);
extern void objAudioFn_800393f8(u8*, u8*, int, int, int, int);
extern int Obj_AllocObjectSetup(int a, int b);
extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void* obj);
extern int sprintf(char* buf, const char* fmt, ...);
extern f32 lbl_803E22A0;
extern void viewFn_80129cbc(f32 a, f32 b, f32 c);
extern int* Obj_GetActiveModel(void* obj);
extern f32 lbl_803E2408;
extern void* lbl_803DD984;
extern f32 timeDelta;
extern u32 lbl_803DDA00;
extern u32 lbl_803DDA08;
extern u16 debugPrintXpos;
extern u16 debugPrintYpos;
extern void Music_Trigger(s32 triggerId, s32 mode);
extern u8 lbl_803AB118[];
extern s16 lbl_803DDA40;
extern u32 lbl_803DDA3C;
extern u32 lbl_803DDA38;
extern u32 lbl_803DDA34;
extern void OSResumeThread(u8 * thread);
extern void OSSetErrorHandler(int kind, void* handler);
extern void OSCreateThread(u8* thread, void* entry, void* arg, void* stack_top, int stack_size, int prio, int flags);
extern void fn_80137DF8(void);
extern u8 lbl_803AB428[];
extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int model, int channel, f32 weight);
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E4;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;
extern f32 lbl_803DD99C;
extern u16 lbl_803DBC0A;
extern u8 enableDebugText;
extern u16* debugDrawFrameBuffer;
extern void DCStoreRange(void* p, u32 nBytes);
extern u16* externalFrameBuffer1;
extern u16* externalFrameBuffer0;
extern u8 lbl_8031D060[];
extern void selectTexture(char* tex, int slot);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
extern void gxDebugTextureFn_80078c1c(void);
extern u32 lbl_803DD9F8;
extern int lbl_803DDA0C;
extern f32 lbl_803DD9E8;
extern f32 lbl_803DD9EC;
extern u8 lbl_8031CFA0[];
extern f32 lbl_803E2390;
extern f32 lbl_803E2394;
extern f32 lbl_803E2398;
extern f32 lbl_803E239C;
extern f32 lbl_803E23A0;
extern f32 lbl_803E23A4;
extern int getButtonsHeld(int p);
extern void GXSetTevColor(int id, int* color);
extern void setTextColor(int p);
extern u16 lbl_803DDA14;
extern u16 lbl_803DDA16;
extern u16 lbl_803DBC10;
extern u8 lbl_803DD9F0;
extern u8 lbl_803DD9F1;
extern u8 lbl_803DD9F2;
extern u8 lbl_803DD9F3;
extern u16 lbl_803DD9F6;
extern int lbl_803DDA10;
extern void drawScaledTexture(char* tex, f32 x, f32 y, int alpha, int s, int w, int h, int mode);
extern u16* debugFrameBuffer;
extern char lbl_803DBC18;
extern char lbl_803DBC1C;
extern char lbl_803DBC20;
extern char lbl_803DBC28;
extern char lbl_803DBC30;
extern char lbl_803DBC34;
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int level);
extern void VISetPreRetraceCallback(void* cb);
extern void VISetPostRetraceCallback(void* cb);
extern void GXSetBreakPtCallback(void* cb);
extern void __GXAbortWaitPECopyDone(void);
extern void VISetNextFrameBuffer(void* fb);
extern void VIFlush(void);
extern void VIWaitForRetrace(void);
extern u16 lbl_803DD9F4;
extern u32 lbl_803DDA04;
extern u32 lbl_803DD9FC;

void FUN_80132034(void)
{
    bool bVar1;

    bVar1 = false;
    if ((DAT_803de5c4 == '\x02') && (DAT_803dc818 != '\0'))
    {
        bVar1 = true;
    }
    if (!bVar1)
    {
        return;
    }
    DAT_803de5a8 = 5;
    return;
}

void FUN_801334d4(void)
{
    FUN_80053754();
    FUN_80053754();
    return;
}

void FUN_80134bc4(void)
{
    DAT_803de62b = 0;
    return;
}

void FUN_80135810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  char* param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

void FUN_80135814(void)
{
    return;
}

void FUN_80135c48(undefined2 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4)
{
    DAT_803de6b4 = param_4;
    DAT_803de6b8 = param_3;
    DAT_803de6bc = param_2;
    DAT_803de6c0 = param_1;
    FUN_80246dcc(-0x7fc54288);
    return;
}

void FUN_80135c84(int param_1, uint param_2)
{
    *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) =
        (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) & 0xbf;
    return;
}

void FUN_8013651c(int param_1)
{
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    *(uint*)(iVar1 + 0x54) = *(uint*)(iVar1 + 0x54) | 0x80000000;
    *(float*)(iVar1 + 0x808) = FLOAT_803e3098;
    return;
}

/* ===== EN v1.0 retargeted leaves ========================================= */

void reportAllocFail(void)
{
}

int dll_3F_frameStart_ret_0(void);

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
f32 fn_80138F78(u8* obj) { return *(f32*)(*(u8**)&((GameObject*)obj)->extra + 0x14); }
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
u32 fn_80138F84(u8* obj) { return *(u32*)(*(u8**)&((GameObject*)obj)->extra + 0x24); }
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
s16 fn_80138F90(u8* obj) { return *(s16*)(*(u8**)&((GameObject*)obj)->extra + 0x414); }
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */
void* trickyGetQueuedPathParticlePos(u8* obj) { return (void*)(*(u8**)&((GameObject*)obj)->extra + 0x408); }

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void);

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void);

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
#pragma scheduling off
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
    u32 flags = *(u32*)(b + 0x54);
    if ((flags & 0x1800) == 0) return;
    stk.dx = *(f32*)(b + 0x408) - *(f32*)(a + 0x18);
    stk.dy = *(f32*)(b + 0x40c) - *(f32*)(a + 0x1c);
    stk.dz = *(f32*)(b + 0x410) - *(f32*)(a + 0x20);
    stk.fk = lbl_803E23E8;
    stk.hx = *(s16*)(a + 0);
    stk.hy = *(s16*)(a + 2);
    stk.hz = *(s16*)(a + 4);
    if ((flags & 0x800) == 0)
    {
        while (i-- != 0)
        {
            (*gPartfxInterface)->spawnObject(a, 0x533, &stk, 2, -1, NULL);
        }
        *(u32*)(b + 0x54) = *(u32*)(b + 0x54) & ~0x1000LL;
    }
}

int trickySelectQueuedCommandTarget(u8* state, int commandType)
{
    extern f32 getXZDistance(f32 * a, f32 * b);
    extern f32 lbl_803E2418;
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
            f32 dist = getXZDistance((f32*)(*(u8**)&((TrickyState*)state)->playerObj + 0x18),
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
        u32 pathMask = 0xfffffbff;
        if (((TrickyState*)state)->unk28 != targetPos)
        {
            ((TrickyState*)state)->unk28 = targetPos;
            ((TrickyState*)state)->stateFlags = ((TrickyState*)state)->stateFlags & pathMask;
            ((TrickyState*)state)->unkD2 = 0;
        }
    }

    state[0xa] = 0;
    return 1;
}

/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
int trickyFn_80138f14(u8* obj)
{
    u8* b = ((GameObject*)obj)->extra;
    if ((u32)GameBit_Get(0x4E4) != 0u)
    {
        ((TrickyImpressState*)b)->unk54 |= 0x10000LL;
        if ((((TrickyImpressState*)b)->unk54 & 0x10) != 0u)
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
    lbl_803DD9D8 = lbl_803E23B8;
    lbl_803DD9DC = lbl_803E23B8;
    lbl_803DD9E0 = 0;
    lbl_803DD9E1 = 0;
    lbl_803DDA24 = textureLoadAsset(0x25D);
    lbl_803DDA20 = textureLoadAsset(1);
    lbl_803DDA1C = textureLoadAsset(2);
    debugLogEnd = debugLogBuffer;
}

/* EN v1.0 0x80137520  size: 128b  Emit a SetColor record (tag 0x81 +
 * 4 RGBA bytes + 0 terminator) into the debug log; aborts when the
 * record counter at lbl_803DD9E4 has already exceeded 0xFA. */
void debugPrintSetColor(u8 r, u8 g, u8 b, u8 a)
{
    int n;
    u8* p;
    n = lbl_803DD9E4 + 1;
    lbl_803DD9E4 = n;
    if (n > 0xfa) return;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = 0x81;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = r;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = g;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = b;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = a;
    p = (u8*)debugLogEnd;
    debugLogEnd = p + 1;
    *p = 0;
}

/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via objAudioFn_800393f8) only when:
 *   - bit 0x40 of obj->_b8->_58 is clear,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma peephole off
int fn_80138920(u8* obj, int arg1, int arg2)
{
    u8* b = ((GameObject*)obj)->extra;
    s16 v;
    if ((u32)((b[0x58] >> 6) & 1) != 0u) return 0;
    v = ((GameObject*)obj)->anim.currentMove;
    if (v < 48)
    {
        if (v >= 41)
        {
            return 0;
        }
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) return 0;
    objAudioFn_800393f8(obj, b + 936, arg1, arg2, -1, 0);
    return 1;
}

__declspec(section ".sdata") extern char lbl_803DBBF0[];

void fn_80133F70(void* obj)
{
    char buf[12];
    f32 threshold;
    int a;
    int b;
    int c;
    void* player;
    void* nearest;

    threshold = lbl_803E22A0;
    a = 0;
    b = 0;
    c = 0;
    if (gameTimerIsRunning())
    {
        gameTimerRun(obj);
    }
    player = (void*)Obj_GetPlayerObject();
    nearest = (void*)ObjGroup_FindNearestObject(9, player, &threshold);
    if (nearest != NULL)
    {
        ((void (*)(void*, int*, int*, int*))(*(void***)((GameObject*)nearest)->anim.dll)[21])(nearest, &a, &b, &c);
    }
    b = c - (b - a);
    if (b < 0)
    {
        b = 0;
    }
    sprintf(buf, lbl_803DBBF0, b);
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

#pragma scheduling on
void fn_80137948(char* fmt, ...)
{
}

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */
void Minimap_release(void);

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
    ((TrickyImpressState*)b)->unk54 |= 0x80000000;
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
    yp = lbl_803DDA08 & 0xffff;
    debugPrintYpos = (u16)yp;
    xp = lbl_803DDA00 & 0xffff;
    debugPrintXpos = (u16)xp;
}

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */
#pragma scheduling on
#pragma peephole on
void fn_80138908(int* obj, u8 v)
{
    u8* x = ((GameObject*)obj)->extra;
    u8 b = *(u8*)(x + 0x58);
    *(u8*)(x + 0x58) = (u8)((b & ~0x40) | ((v & 1) << 6));
}

void titlescreen_free(u8* obj);

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &lbl_803AB118. */
#pragma scheduling off
void fn_801388D0(s16 a, u32 b, u32 c, u32 d)
{
    lbl_803DDA40 = a;
    lbl_803DDA3C = b;
    lbl_803DDA38 = c;
    lbl_803DDA34 = d;
    OSResumeThread(lbl_803AB118);
}

void fn_80137D28(void)
{
    OSSetErrorHandler(0, (void*)fn_801388D0);
    OSSetErrorHandler(1, (void*)fn_801388D0);
    OSSetErrorHandler(2, (void*)fn_801388D0);
    OSSetErrorHandler(11, (void*)fn_801388D0);
    OSSetErrorHandler(13, (void*)fn_801388D0);
    OSSetErrorHandler(15, (void*)fn_801388D0);
    OSSetErrorHandler(3, (void*)fn_801388D0);
    OSSetErrorHandler(5, (void*)fn_801388D0);
    OSCreateThread(lbl_803AB118, (void*)fn_80137DF8, 0, lbl_803AB428 + 4096, 4096, 0, 1);
}

int trickyFindNearestUsableBaddie(int p1, f32 maxRadius, int p2)
{
    extern int dll_19_func1B(int);
    extern int* gBaddieControlInterface;
    extern MapEventInterface** gMapEventInterface;
    extern f32 fn_8014C5D0(int);
    extern int*ObjGroup_GetObjects(int, int*);
    extern int ObjGroup_ContainsObject(int, int);
    extern f32 vec3f_distanceSquared(int, int);
    extern f32 lbl_803E23DC;
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
            if (*(s16*)(*objs + 0x46) != 2129)
            {
                if ((*gMapEventInterface)->shouldNotSaveTime(
                    *(int*)((char*)data + 0x14)) != 0)
                {
                    if (p2 == 0)
                    {
                        s16 m = *(s16*)(*objs + 0x46);
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
    extern void*Obj_GetActiveModel(int);
    extern void Obj_SetModelColorOverrideRecursive(int, int, int, int, int, int);
    extern f32 timeDelta;
    extern f32 lbl_803E23DC;
    extern f32 lbl_803E23E0;
    extern f32 lbl_803E23E8;
    extern f32 lbl_803E2408;
    extern f32 lbl_803E240C;
    u8 ratio = (u8)((s32) * (u8*)(*(int*)(p2 + 0) + 2) / 10);

    if (*(u8*)(p2 + 0x82c) != ratio)
    {
        f32 t;
        if (GameBit_Get(1005) == 0)
        {
            GameBit_Set(1005, 1);
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
            *(u32*)(p2 + 0x54) = *(u32*)(p2 + 0x54) | 0x4000;
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
    return;
}

#define TUMBLEWEED_BLEND_FLAGS_OFFSET 0x82e
#define TUMBLEWEED_BLEND_WEIGHT_OFFSET 0x830
#define TUMBLEWEED_BLEND_VELOCITY_OFFSET 0x834
#define TUMBLEWEED_BLEND_FLAG_PENDING 0x80
#define TUMBLEWEED_BLEND_FLAG_ACTIVE 0x40

/* Tricky_updateBlendChannelWeight: weighted blend-channel animator. On state[0x82e] bit 0x80,
 * primes channel 1 (weight 0, target weight ratio at +0x830) and latches
 * the active flag. While bit 0x40 is set, ramps state[0x830] toward
 * (s8)data[0] / (s8)data[1] with acceleration lbl_803E23E4 and damping
 * lbl_803E23F0, clamps to [0, lbl_803E23E8], and pushes the result to the
 * model's blend channel 1 as `lbl_803E23F8 * weight - lbl_803E23E8`. */
void Tricky_updateBlendChannelWeight(int obj, u8* state)
{
    extern void* Obj_GetActiveModel(int obj);
    int model;
    f32 target;
    Obj_GetActiveModel(obj);
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 7) & 1) != 0)
    {
        model = (int)Obj_GetActiveModel(obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, lbl_803E23DC, 0x21);
        *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E0;
        ObjModel_SetBlendChannelWeight(model, 0, lbl_803E23DC);
        state[TUMBLEWEED_BLEND_FLAGS_OFFSET] =
            state[TUMBLEWEED_BLEND_FLAGS_OFFSET] & ~TUMBLEWEED_BLEND_FLAG_PENDING;
        state[TUMBLEWEED_BLEND_FLAGS_OFFSET] =
            state[TUMBLEWEED_BLEND_FLAGS_OFFSET] | TUMBLEWEED_BLEND_FLAG_ACTIVE;
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
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < lbl_803E23DC)
            {
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23DC;
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

volatile PPCWGPipe GXWGFifo : (0xCC008000);

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
        buf[*(u8*)(b + 0x7bc) >> 6 & 3] = 1;
    }
    v1 = *(void**)(b + 0x7b0);
    if (v1 != NULL)
    {
        buf[*(u8*)(b + 0x7bc) >> 4 & 3] = 1;
    }
    v2 = *(void**)(b + 0x7b8);
    if (v2 != NULL)
    {
        buf[*(u8*)(b + 0x7bc) >> 2 & 3] = 1;
    }
    if (buf[0] == -1)
    {
        if (v0 != NULL)
        {
            ObjLink_DetachChild(a, (int)v0);
            ObjLink_AttachChild(a, *(int*)(b + 0x7a8), 0);
            ((AnimSlots*)(b + 0x7bc))->s0 = 0;
        }
        else if (v1 != NULL)
        {
            ObjLink_DetachChild(a, (int)v1);
            ObjLink_AttachChild(a, *(int*)(b + 0x7b0), 0);
            ((AnimSlots*)(b + 0x7bc))->s1 = 0;
        }
        else if (v2 != NULL)
        {
            ObjLink_DetachChild(a, (int)v2);
            ObjLink_AttachChild(a, *(int*)(b + 0x7b8), 0);
            ((AnimSlots*)(b + 0x7bc))->s2 = 0;
        }
    }
}

void fn_80137A00(int p1, int p2, u8* grid, int p4)
{
    int i;
    int bit;
    int c0;
    int c1;
    int row0;
    int row1;
    int a0;
    int a1;
    int a2;
    int a3;

    if (enableDebugText != 0)
    {
        i = 0;
        row1 = (p2 + 1) * 0x280;
        row0 = p2 * 0x280;
        for (; i < 5; i++)
        {
            bit = 0;
            c0 = p1 + row0;
            a0 = c0;
            a1 = c0 + 1;
            c1 = p1 + row1;
            a2 = c1;
            a3 = c1 + 1;
            for (; bit < 8; bit++)
            {
                if (((1 << bit) & *grid) != 0)
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
            grid++;
        }
    }
}

#pragma peephole on
void debugPrintfxy(int x, int y, char* fmt, ...)
{
    int xx;
    int yy;
    u16* saved;
    int x0 = x;
    u8* p1;
    u8* p2;
    va_list args;
    char buf[272];

    if (enableDebugText != 0)
    {
        xx = x0;
        yy = y;
        va_start(args, fmt);
        vsprintf(buf, fmt, args);
        saved = debugDrawFrameBuffer;
        p1 = (u8*)buf - 1;
        p2 = (u8*)buf - 1;
        while (p1++, *++p2 != 0)
        {
            switch (*p1)
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
                if (*p1 >= 0x61 && *p1 <= 0x7a)
                {
                    *p1 = *p1 - 0x20;
                }
                if (*p1 >= 0x21 && *p1 <= 0x5a)
                {
                    debugDrawFrameBuffer = externalFrameBuffer0;
                    fn_80137A00(xx, yy, lbl_8031D060 + (*p1 - 0x21) * 5, -1);
                    debugDrawFrameBuffer = externalFrameBuffer1;
                    fn_80137A00(xx, yy, lbl_8031D060 + (*p1 - 0x21) * 5, -1);
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
    f32 sc;

    if (c <= 0x3f)
    {
        if (lbl_803DD9F8 != 0)
        {
            if (lbl_803DDA0C != 0)
            {
                selectTexture((char*)lbl_803DDA24, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA24 + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA24 + 0xc));
            }
            lbl_803DD9F8 = 0;
        }
        c -= 0x21;
    }
    else if (c <= 0x5f)
    {
        if (lbl_803DD9F8 != 1)
        {
            if (lbl_803DDA0C != 0)
            {
                selectTexture((char*)lbl_803DDA20, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA20 + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA20 + 0xc));
            }
            lbl_803DD9F8 = 1;
        }
        c -= 0x40;
    }
    else if (c <= 0x7f)
    {
        if (lbl_803DD9F8 != 2)
        {
            if (lbl_803DDA0C != 0)
            {
                selectTexture((char*)lbl_803DDA1C, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA1C + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32) * (u16*)((char*)lbl_803DDA1C + 0xc));
            }
            lbl_803DD9F8 = 2;
        }
        c -= 0x60;
    }
    tbl = lbl_8031CFA0 + lbl_803DD9F8 * 0x40;
    first = tbl[c * 2];
    c = tbl[c * 2 + 1] - first + 1;
    if (lbl_803DDA0C != 0)
    {
        px = (int)((f32)debugPrintYpos * (lbl_803DD9D8 + (f32)lbl_803DD9E0));
        py = (int)((f32)debugPrintXpos * (lbl_803DD9DC + (f32)lbl_803DD9E1));
        gxDebugTextureFn_80078c1c();
        sc = lbl_803DD9EC;
        textRenderChar(px << 2, py << 2,
                       (int)(lbl_803E2398 * ((f32)c * (lbl_803DD9D8 + (f32)lbl_803DD9E0) + (f32)px)),
                       (int)(lbl_803E2398 * (lbl_803E239C * (lbl_803DD9DC + (f32)lbl_803DD9E1) + (f32)py)),
                       (f32)(first << 5) * sc,
                       lbl_803E23A0,
                       sc * (f32)((first + c) << 5),
                       lbl_803E23A4 * lbl_803DD9E8);
    }
    return c;
}

extern int ObjGroup_FindNearestObject(int type, int obj, f32* distOut);

#pragma peephole off
int fn_80136E00(int p1, u8* p)
{
    u8 c;
    int w;
    u16 x2;
    u16 y;
    u16 y0;
    u16 y1;
    u16 x0;
    u32 ca;
    u32 cb;
    u32 cc;
    f32 sc;
    int rm;
    u8 c0;
    u8 c1;
    u8 c2;
    u8 c3;
    u8 colb1[4];
    u32 colw1;
    u8 colb2[4];
    u32 colw2;
    u8 colb3[4];
    u32 colw3;
    u8* start = p;

    while ((c = *p++) != 0)
    {
        w = 0;
        switch (c)
        {
        case 0x83:
            lbl_803DDA10 = 0;
            break;
        case 0x84:
            lbl_803DDA10 = 1;
            break;
        case 0x81:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (lbl_803DDA0C != 0)
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
            lbl_803DD9E0 = p[0];
            lbl_803DD9E1 = p[1];
            p += 2;
            break;
        case 0x85:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (lbl_803DDA0C == 0)
            {
                lbl_803DD9F3 = c0;
                lbl_803DD9F2 = c1;
                lbl_803DD9F1 = c2;
                lbl_803DD9F0 = c3;
                setTextColor(p1);
            }
            break;
        case 0x82:
            if (lbl_803DDA0C == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0)
                {
                    if (y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    sc = lbl_803DD9D8 + (f32)lbl_803DD9E0;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb1[0] = lbl_803DD9F3;
                    colb1[1] = lbl_803DD9F2;
                    colb1[2] = lbl_803DD9F1;
                    colb1[3] = lbl_803DD9F0;
                    colw1 = *(u32*)colb1;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw1);
                }
            }
            debugPrintYpos = p[0];
            debugPrintYpos |= p[1] << 8;
            debugPrintXpos = p[2];
            debugPrintXpos |= p[3] << 8;
            p += 4;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
            break;
        case 0x86:
            lbl_803DBC10 = p[0];
            lbl_803DBC10 |= p[1] << 8;
            p += 2;
            break;
        case 0x20:
            w = 6;
            break;
        case 0xa:
            if (lbl_803DDA0C == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0)
                {
                    if (y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    sc = lbl_803DD9D8 + (f32)lbl_803DD9E0;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb2[0] = lbl_803DD9F3;
                    colb2[1] = lbl_803DD9F2;
                    colb2[2] = lbl_803DD9F1;
                    colb2[3] = lbl_803DD9F0;
                    colw2 = *(u32*)colb2;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw2);
                }
            }
            debugPrintYpos = (u16)lbl_803DDA08;
            debugPrintXpos += 0xb;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
            break;
        case 9:
            rm = debugPrintYpos % lbl_803DBC10;
            if (rm == 0)
            {
                w = lbl_803DBC10;
            }
            else
            {
                w = lbl_803DBC10 - rm;
            }
            break;
        default:
            w = fn_80136A40(p1, c);
            break;
        }
        if (lbl_803DDA10 != 0 && c >= 0x20 && c <= 0x7f)
        {
            w = 7;
        }
        debugPrintYpos += w;
        if ((f32)debugPrintYpos * (sc = lbl_803DD9D8 + (f32)lbl_803DD9E0) >
            (f32)(int)(lbl_803DD9F6 - 0x10))
        {
            if (lbl_803DDA0C == 0)
            {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0)
                {
                    if (y0 >= 2)
                    {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb3[0] = lbl_803DD9F3;
                    colb3[1] = lbl_803DD9F2;
                    colb3[2] = lbl_803DD9F1;
                    colb3[3] = lbl_803DD9F0;
                    colw3 = *(u32*)colb3;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw3);
                }
            }
            debugPrintYpos = (u16)lbl_803DDA08;
            debugPrintXpos += 0xb;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
        }
    }
    return p - start;
}

/* EN v1.0 0x80137DF8  size: 2776b  fn_80137DF8: error display thread.
 * Clears the debug framebuffer, prints the exception type, DSISR/SRR0,
 * stack trace and GPR dump via debugPrintfxy, draws the underline and
 * box pixels directly into the framebuffer, and flips buffers forever. */
void fn_80137DF8(void)
{
    char* strs = (char*)lbl_8031D060;
    u32* sp;
    int depth;
    int hold;
    int x, col;
    int row;
    int h, h2;
    int b;
    int y;
    int n;
    u32 cnt;
    u32* p;
    u8 lvl;
    u32 r, rr;
    int rp;
    int rows;

    sp = NULL;
    depth = 0;
    hold = 0xb4;
    if (enableDebugText != 0)
    {
        debugDrawFrameBuffer = externalFrameBuffer0;
        debugFrameBuffer = externalFrameBuffer1;
        lvl = (u8)OSDisableInterrupts();
        VISetPreRetraceCallback(NULL);
        VISetPostRetraceCallback(NULL);
        GXSetBreakPtCallback(NULL);
        __GXAbortWaitPECopyDone();
        OSRestoreInterrupts(lvl);
        while (1)
        {
            if (enableDebugText != 0)
            {
                x = 0;
                col = x;
                for (; x < 0x280; x++)
                {
                    for (row = 0; row < 0x96000; row += 0x500)
                    {
                        *(u16*)(col + (char*)debugDrawFrameBuffer + row) = 0x1080;
                    }
                    col += 2;
                }
            }
            debugPrintfxy(0x10, 0x15, strs + 0x140, fn_80137DF8);
            debugPrintfxy(0x10, 0x2a, strs + 0x154);
            switch ((u16)lbl_803DDA40)
            {
            case 0:
                debugPrintfxy(0xa0, 0x2a, strs + 0x160);
                break;
            case 1:
                debugPrintfxy(0xa0, 0x2a, strs + 0x170);
                break;
            case 2:
                debugPrintfxy(0xa0, 0x2a, &lbl_803DBC18);
                break;
            case 3:
                debugPrintfxy(0xa0, 0x2a, &lbl_803DBC1C);
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
            debugPrintfxy(0x10, 0x3f, &lbl_803DBC20, *(u32*)(lbl_803DDA3C + 0x198));
            debugPrintfxy(0x10, 0x4b, &lbl_803DBC28, *(u32*)(lbl_803DDA3C + 4));
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
            p = (u32*)**(u32**)(lbl_803DDA3C + 4);
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
                if (rows > 0)
                {
                    for (n = 0x280; n != 0; n--)
                    {
                        debugDrawFrameBuffer[h] = 0xc080;
                        debugDrawFrameBuffer[h2] = 0xc080;
                        h++;
                        h2++;
                    }
                }
                else
                {
                    for (n = 0x280; n != 0; n--)
                    {
                        debugDrawFrameBuffer[h] = 0xc080;
                        h++;
                    }
                }
            }
            if (enableDebugText != 0)
            {
                b = 0x12700;
                rows = y + 0x4c;
                cnt = rows - 0x3b;
                if (rows > 0x3b)
                {
                    do
                    {
                        *(u16*)((char*)debugDrawFrameBuffer + b + 0x1e0) = 0xc080;
                        b += 0x500;
                    }
                    while (--cnt != 0);
                }
            }
            y += 0x51;
            if (sp == NULL)
            {
                sp = *(u32**)(lbl_803DDA3C + 4);
                depth = 0;
            }
            else if (hold-- == 0)
            {
                hold = 0xb4;
                sp = (u32*)*sp;
                depth++;
                if (sp == (u32*)0xffffffff)
                {
                    sp = *(u32**)(lbl_803DDA3C + 4);
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
                rp = lbl_803DDA3C + rr * 4;
                debugPrintfxy(0x10, y + 0x18, strs + 0x22c,
                              *(u32*)(lbl_803DDA3C + (r & 0xff) * 4), *(u32*)(rp + 4),
                              *(u32*)(rp + 8), *(u32*)(rp + 0xc));
                y += 0x24;
                rp = lbl_803DDA3C + rr * 4;
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
                for (row = 0; row < 0x96000; row += 0x500)
                {
                    *(u16*)(col + (char*)debugDrawFrameBuffer + row) = 0x1080;
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

/* EN v1.0 0x801375C8  size: 736b  debugPrintDraw: lay out the debug log
 * twice (measure pass then draw pass), drawing the backing rect between
 * the passes when the log produced any extent. */
void debugPrintDraw(int ctx)
{
    u8* p;
    int pass;
    u32 res;
    u32 x1;
    u32 xs, ys;
    u32 yv;
    u32 y2;
    int ta, tb;
    u32 xa, xb, ya, yb;
    f32 scale;
    u32 colw;
    u32 colb;

    res = getScreenResolution();
    lbl_803DD9F4 = (u16)(res >> 0x10);
    lbl_803DD9F6 = (u16)res;
    GXSetScissor(0, 0, lbl_803DD9F6, lbl_803DD9F4);
    if (lbl_803DD9F6 <= 0x140)
    {
        lbl_803DDA08 = 0x10;
        lbl_803DDA04 = lbl_803DD9F6 - 0x10;
    }
    else
    {
        lbl_803DDA08 = 0x20;
        lbl_803DDA04 = lbl_803DD9F6 - 0x20;
    }
    if (lbl_803DD9F4 <= 0xf0)
    {
        lbl_803DDA00 = 0x10;
        lbl_803DD9FC = lbl_803DD9F4 - 0x10;
    }
    else
    {
        lbl_803DDA00 = 0x20;
        lbl_803DD9FC = lbl_803DD9F4 - 0x20;
    }
    gxDebugTextureFn_80078c1c();
    p = debugLogBuffer;
    debugPrintYpos = (u16)lbl_803DDA08;
    debugPrintXpos = (u16)lbl_803DDA00;
    lbl_803DD9F8 = 0xffffffff;
    pass = 0;
    lbl_803DDA10 = pass;
    lbl_803DDA16 = debugPrintYpos;
    lbl_803DDA14 = debugPrintXpos;
    for (; p != debugLogEnd;)
    {
        lbl_803DDA0C = pass;
        p += fn_80136E00(ctx, p);
    }
    x1 = debugPrintXpos + 0xa;
    yv = debugPrintYpos;
    xs = lbl_803DDA14;
    ys = lbl_803DDA16;
    ta = !(yv - ys);
    tb = !(x1 - xs);
    if ((ta | tb) == 0)
    {
        if (ys >= 2)
        {
            ys -= 2;
        }
        y2 = yv + 2;
        scale = lbl_803DD9D8 + (f32)lbl_803DD9E0;
        xa = (u32)((f32)ys * scale);
        xb = (u32)((f32)y2 * scale);
        scale = lbl_803DD9DC + (f32)lbl_803DD9E1;
        ya = (u32)((f32)xs * scale);
        yb = (u32)((f32)x1 * scale);
        ((u8*)&colb)[0] = lbl_803DD9F3;
        ((u8*)&colb)[1] = lbl_803DD9F2;
        ((u8*)&colb)[2] = lbl_803DD9F1;
        ((u8*)&colb)[3] = lbl_803DD9F0;
        colw = colb;
        hudDrawRect(xa, ya, xb, yb, &colw);
    }
    p = debugLogBuffer;
    debugPrintYpos = (u16)lbl_803DDA08;
    debugPrintXpos = (u16)lbl_803DDA00;
    lbl_803DD9F8 = 0xffffffff;
    lbl_803DDA10 = 0;
    pass = 1;
    for (; p != debugLogEnd;)
    {
        lbl_803DDA0C = pass;
        p += fn_80136E00(ctx, p);
    }
    debugLogEnd = debugLogBuffer;
    lbl_803DD9E4 = 0;
}
