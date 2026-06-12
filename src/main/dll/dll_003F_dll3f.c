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





extern int ObjGroup_FindNearestObject();
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

/*
 * --INFO--
 *
 * Function: Minimap_update
 * EN v1.0 Address: 0x80132024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801323AC
 * EN v1.1 Size: 5296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



extern void* Obj_GetPlayerObject(void);


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: FUN_80132034
 * EN v1.0 Address: 0x80132034
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80133868
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_801334d4
 * EN v1.0 Address: 0x801334D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80134B90
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334d4(void)
{
    FUN_80053754();
    FUN_80053754();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_80134bc4
 * EN v1.0 Address: 0x80134BC4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80136C5C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bc4(void)
{
    DAT_803de62b = 0;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_80135810
 * EN v1.0 Address: 0x80135810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137C30
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  char* param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135814
 * EN v1.0 Address: 0x80135814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137CD0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135814(void)
{
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_80135c48
 * EN v1.0 Address: 0x80135C48
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80138C58
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c48(undefined2 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4)
{
    DAT_803de6b4 = param_4;
    DAT_803de6b8 = param_3;
    DAT_803de6bc = param_2;
    DAT_803de6c0 = param_1;
    FUN_80246dcc(-0x7fc54288);
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c84
 * EN v1.0 Address: 0x80135C84
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80138C90
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c84(int param_1, uint param_2)
{
    *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) =
        (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) & 0xbf;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8013651c
 * EN v1.0 Address: 0x8013651C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80139280
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013651c(int param_1)
{
    int iVar1;

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    *(uint*)(iVar1 + 0x54) = *(uint*)(iVar1 + 0x54) | 0x80000000;
    *(float*)(iVar1 + 0x808) = FLOAT_803e3098;
    return;
}


/* ===== EN v1.0 retargeted leaves ========================================= */

extern u8 warpstoneUIState;

/* 4-byte and 8-byte trivial leaves. */
void dll_3F_frameEnd_nop(void)
{
}

void Credits_render(void);




int dll_3F_frameStart_ret_0(void) { return 0; }
u8 shouldShowCredits(void);

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */

/* EN v1.0 0x801344F0  size: 12b  u8 setter writing arg low byte to
 * warpstoneUIState. */
#pragma peephole off
#pragma peephole reset

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void);

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void);

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_getObjectTypeId: returns 74 if
 * obj->_46 (s16) is in [1917, 1920], else returns 0. */
int titlescreen_getObjectTypeId(u8* obj);

extern void titlescreen_free(u8 * obj);
extern void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void titlescreen_update(u8 * obj);
extern void titlescreen_init(u8 * obj, u8 * p);
extern void titlescreen_release(void);
extern void titlescreen_initialise(void);

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

extern void* lbl_803DD974;

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at lbl_803DD9D4 and walk the 19-slot table at lbl_803A9F98
 * releasing each non-null entry, then clear the busy byte at
 * lbl_803DD992. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void);
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x8013695C  size: 228b  titlescreen_initialise: reset state
 * bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * lbl_803DC968), identity the matrix, then load the 19-entry texture
 * table from the id list at lbl_8031CDE8 into lbl_803A9F98. */
#pragma scheduling off
#pragma peephole off
void titlescreen_initialise(void);
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x80135C2C  size: 152b  titlescreen_render: when visible and
 * ready, render via objRenderFn; once the credits flag fires, set the
 * one-shot trigger 0x57 and release the attract-mode movie buffers. */
#pragma scheduling off
#pragma peephole off
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset
#pragma scheduling reset



/* EN v1.0 0x801367A8  size: 252b  titlescreen_init: seed the object's
 * state from its descriptor id (obj->_46), pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
#pragma scheduling off
#pragma peephole off
void titlescreen_init(u8* obj, u8* p);
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x80139164  size: 252b  Tricky_emitQueuedPathParticles: when b->_54 carries the
 * spawn flag, build a particle descriptor on the stack from a's heading
 * and the delta to b's position, then emit it 20 times via the partfx
 * interface and clear the flag. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134388  size: 68b  Acquire two buffers and prime the
 * float at lbl_803DD968. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset




/* EN v1.0 0x80137998  size: 104b  Title-screen system init. Calls
 * getScreenResolution, primes the two float counters, clears two state bytes,
 * acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x80137520  size: 128b  Emit a SetColor record (tag 0x81 +
 * 4 RGBA bytes + 0 terminator) into the debug log; aborts when the
 * record counter at lbl_803DD9E4 has already exceeded 0xFA. */
#pragma scheduling off
#pragma scheduling reset


/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via objAudioFn_800393f8) only when:
 *   - bit 0x40 of obj->_b8->_58 is clear,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void* obj);
extern int sprintf(char* buf, const char* fmt, ...);
extern f32 lbl_803E22A0;
__declspec(section ".sdata") extern char lbl_803DBBF0[];

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

extern void viewFn_80129cbc(f32 a, f32 b, f32 c);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* Variadic debug logger: append formatted text while the debug arena has room. */
#pragma scheduling off
#pragma scheduling reset

/* Variadic debug-print sink: retail keeps only the ABI varargs spill frame. */

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at lbl_803A9FE4 and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma scheduling off
#pragma scheduling reset

extern void* lbl_803DD960;
/* lbl_803DD940 declared later as void* */

/* EN v1.0 0x80133F40  size: 48b  Acquire a 0xBE5-byte buffer via
 * textureLoadAsset into lbl_803DD940; reset frame counter at lbl_803DD938. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */
void dll_3F_release(void)
{
    textureFree(lbl_803DD960);
}

/* EN v1.0 0x80134070  size: 40b  Acquire 0x47A-byte buffer into
 * lbl_803DD960. */
#pragma scheduling off
void dll_3F_initialise(void)
{
    lbl_803DD960 = textureLoadAsset(0x47A);
}
#pragma scheduling reset

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */
void Credits_release(void);

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */


/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x80134834  size: 60b  Acquire two buffer slots and prime
 * the float at lbl_803DD97C with the constant from lbl_803E22E0. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch showCredits = 1 and zero five halfword/byte counters. */
#pragma scheduling off
#pragma scheduling reset

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
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(0x3a, 0) and clear showCredits. */

void titlescreen_free(u8* obj);

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &lbl_803AB118. */
#pragma scheduling off
#pragma scheduling reset

/* EN v1.0 0x801334E0  size: 60b  Gate: when lbl_803DD944 == 2 (s8 compare)
 * and lbl_803DBBB0 != 0, latch lbl_803DD928 = 5 and return 1; else
 * return 0 without touching the latch. */
#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset



/* Tricky_updateBlendChannelWeight: weighted blend-channel animator. On state[0x82e] bit 0x80,
 * primes channel 1 (weight 0, target weight ratio at +0x830) and latches
 * the active flag. While bit 0x40 is set, ramps state[0x830] toward
 * (s8)data[0] / (s8)data[1] with acceleration lbl_803E23E4 and damping
 * lbl_803E23F0, clamps to [0, lbl_803E23E8], and pushes the result to the
 * model's blend channel 1 as `lbl_803E23F8 * weight - lbl_803E23E8`. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset




volatile PPCWGPipe GXWGFifo : (0xCC008000);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x80135CC8  size: 2784b  titlescreen_update: drive the title
 * screen actor anim state machine, the per-actor footstep/voice sfx flag
 * grid at lbl_803A9F50, the random blink blend, and the one-shot envfx/sky
 * setup. */
#pragma scheduling off
#pragma peephole off
void titlescreen_update(u8* obj);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset




#pragma scheduling off
#pragma peephole off
#pragma peephole reset








#pragma peephole off
#pragma peephole reset


#pragma peephole off
#pragma peephole reset


#pragma peephole off
#pragma peephole reset





extern int ObjGroup_FindNearestObject(int type, int obj, f32* distOut);

#pragma peephole off
#pragma peephole reset


#pragma peephole off
#pragma peephole reset


#pragma peephole off
#pragma peephole reset


/* EN v1.0 0x80137DF8  size: 2776b  fn_80137DF8: error display thread.
 * Clears the debug framebuffer, prints the exception type, DSISR/SRR0,
 * stack trace and GPR dump via debugPrintfxy, draws the underline and
 * box pixels directly into the framebuffer, and flips buffers forever. */
#pragma peephole off
#pragma peephole reset


/* EN v1.0 0x801375C8  size: 736b  debugPrintDraw: lay out the debug log
 * twice (measure pass then draw pass), drawing the backing rect between
 * the passes when the log produced any extent. */
#pragma peephole off
#pragma peephole reset
