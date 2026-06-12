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
extern u32 GameBit_Get(int eventId);


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

void Credits_render(void)
{
}

void Credits_frameEnd(void)
{
}

void WarpstoneUI_frameEnd(void);


/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */


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

extern f32 lbl_803DD968;
extern f32 lbl_803E22A8;
extern u8 lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern void* gameTextGet(s32);


extern s8 lbl_803DBC09;
extern u8 lbl_803DD991;


/* EN v1.0 0x80134388  size: 68b  Acquire two buffers and prime the
 * float at lbl_803DD968. */
#pragma scheduling off
void Credits_initialise(void)
{
    lbl_803DD974 = textureLoadAsset(0xC5);
    lbl_803DD96C = gameTextGet(0x1FD);
    lbl_803DD970 = 0;
    lbl_803DD968 = lbl_803E22A8;
}
#pragma scheduling reset


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


/* Variadic debug-print sink: retail keeps only the ABI varargs spill frame. */

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */


/* lbl_803DD940 declared later as void* */


/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */


/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */
void Credits_release(void)
{
    textureFree(lbl_803DD974);
}

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
void titleScreenFn_801368a4(s8 arg);

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */


/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
extern f32 timeDelta;


/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */


/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(0x3a, 0) and clear showCredits. */

void titlescreen_free(u8* obj);


volatile PPCWGPipe GXWGFifo : (0xCC008000);


#pragma scheduling off
#pragma peephole off
#pragma peephole reset


typedef struct
{
    u16 t0;
    u16 t1;
    u16 t2;
    u16 t3;
    u8 pad8[3];
    u8 alpha;
    f32 y;
} CreditsLine;

typedef struct
{
    CreditsLine lines[9];
    u16 f90;
    u16 f92;
    u8 count;
    u8 pad95[3];
} CreditsPage;

extern CreditsPage gCreditsPages[];
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;

#pragma peephole off
int Credits_frameStart(void)
{
    u8 idx;
    int i;
    f32 cur;
    f32 t;
    f32 frac;
    CreditsPage* page;
    u8 a;

    idx = lbl_803DD970;
    if (idx < 10)
    {
        t = lbl_803DD968;
        lbl_803DD968 = t + timeDelta;
        if (lbl_803DD968 >= (f32)gCreditsPages[idx].f92)
        {
            lbl_803DD970 = idx + 1;
        }
        if (lbl_803DD970 < 10)
        {
            i = 0;
            cur = lbl_803DD968;
            page = &gCreditsPages[lbl_803DD970];
            for (; i < page->count; i++)
            {
                if (cur < (f32)page->lines[i].t0)
                {
                    a = 0;
                }
                else if (cur < (f32)page->lines[i].t1)
                {
                    frac = (cur - (f32)page->lines[i].t0) /
                        (f32)(page->lines[i].t1 - page->lines[i].t0);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    a = lbl_803E22B0 * frac;
                }
                else if (cur < (f32)page->lines[i].t2)
                {
                    a = 0xff;
                }
                else if (cur < (f32)page->lines[i].t3)
                {
                    frac = (cur - (f32)page->lines[i].t2) /
                        (f32)(page->lines[i].t3 - page->lines[i].t2);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    a = 0xff - (int)(lbl_803E22B0 * frac);
                }
                else
                {
                    a = 0;
                }
                page->lines[i].alpha = a;
                if (cur >= (f32)page->lines[i].t0 && cur <= (f32)page->lines[i].t3 &&
                    cur >= (f32)gCreditsPages[lbl_803DD970].f90)
                {
                    page->lines[i].y = lbl_803E22B4 * (timeDelta / lbl_803E22B8) + page->lines[i].y;
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset

extern u32 lbl_803E2200;

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
