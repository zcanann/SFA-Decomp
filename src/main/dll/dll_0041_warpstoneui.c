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

extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);

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

extern u8 warpstoneUIState;

void WarpstoneUI_frameEnd(void)
{
}

void reportAllocFail(void);

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */

/* EN v1.0 0x801344F0  size: 12b  u8 setter writing arg low byte to
 * warpstoneUIState. */
#pragma peephole off
void WarpstoneUI_setState(int val) { warpstoneUIState = (u8)val; }
#pragma peephole reset

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */
void fn_80135814(u32 a, u32 b);

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void);

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void);

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

extern void* lbl_803DD984;
extern void* lbl_803DD980;
extern f32 lbl_803DD97C;
extern f32 lbl_803E22E0;

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */
void WarpstoneUI_release(void)
{
    textureFree(lbl_803DD984);
    textureFree(lbl_803DD980);
}

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
extern f32 lbl_803E22D8;
extern f32 lbl_803E22DC;
extern f32 timeDelta;
#pragma scheduling off
int WarpstoneUI_frameStart(void)
{
    f32 v;
    if (warpstoneUIState == 0)
    {
        lbl_803DD97C = lbl_803DD97C - (lbl_803E22D8 * timeDelta);
    }
    else
    {
        lbl_803DD97C = lbl_803DD97C + (lbl_803E22D8 * timeDelta);
    }
    v = lbl_803DD97C;
    if (v > *(f32*)&lbl_803E22DC)
    {
        lbl_803DD97C = lbl_803E22DC;
    }
    else if (v < *(f32*)&lbl_803E22E0)
    {
        lbl_803DD97C = lbl_803E22E0;
    }
    return 0;
}
#pragma scheduling reset

/* EN v1.0 0x80134834  size: 60b  Acquire two buffer slots and prime
 * the float at lbl_803DD97C with the constant from lbl_803E22E0. */
#pragma scheduling off
void WarpstoneUI_initialise(void)
{
    lbl_803DD984 = textureLoadAsset(0x4FA);
    lbl_803DD980 = textureLoadAsset(0x5E3);
    lbl_803DD97C = lbl_803E22E0;
}
#pragma scheduling reset

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */

void titlescreen_free(u8* obj);

volatile PPCWGPipe GXWGFifo : (0xCC008000);

#pragma scheduling off
#pragma peephole off
int fn_801343CC(u8* src, u8* dst, u8* ids, int count, int* out)
{
    u8* lastDst;
    int n;
    int k;
    u8* idp;
    int yoff;

    lastDst = NULL;
    n = 0;
    k = 0;
    idp = ids;
    for (k = 0; k < count; k++)
    {
        if ((u32)GameBit_Get(*(s16*)idp) != 0)
        {
            n++;
        }
        idp += 4;
    }
    k = 0;
    idp = ids;
    yoff = (count - n) * 0x2a / 2 + 0x52;
    for (n = 0; n < count; n++)
    {
        if ((u32)GameBit_Get(*(s16*)idp) != 0)
        {
            memcpy(dst, src, 0x3c);
            lastDst = dst;
            *(s16*)(dst + 6) = (s16)yoff;
            *(s8*)(dst + 0x1a) = (s8)(k - 1);
            *(s8*)(dst + 0x1b) = (s8)(k + 1);
            *out = n;
            out++;
            dst += 0x3c;
            yoff += 0x2a;
            k++;
        }
        idp += 4;
        src += 0x3c;
    }
    if (lastDst != NULL)
    {
        *(s8*)(lastDst + 0x1b) = -1;
    }
    return k;
}
#pragma peephole reset
#pragma scheduling reset


extern void gameTextFn_80016810(int textId, int a, int b);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset

extern void CMenu_SetFadeCounter(int v);
extern int lbl_803DD978;
extern int lbl_803DBBF8;
extern int lbl_803DBBFC;
extern int lbl_803DBC00;
extern int lbl_803DBC04;

typedef struct
{
    s16 bit;
    u8 b2;
    u8 b3;
} WarpstoneEntry;

extern u8 lbl_8031CC50[];
extern u8 lbl_803A9DD0[];
extern WarpstoneEntry lbl_8031CC38[];
extern int lbl_803A9F38[];
extern int* gTitleMenuLinkInterface;

void WarpstoneUI_showUI(int param_1)
{
    int sel;
    int idx;
    int n;

    CMenu_SetFadeCounter(0);
    switch (warpstoneUIState)
    {
    case 2:
    case 3:
    case 5:
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBBF8);
        break;
    case 1:
        drawTexture(lbl_803DD980, (f32)(int)(lbl_803DBBFC - 0x1d), (f32)(int)(lbl_803DBC00 + 0xd),
                    (int)lbl_803DD97C, 0xff);
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextShow(0x37c);
        gameTextShow(0x37d);
        gameTextShow(0x37e);
        break;
    case 4:
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBC04);
        if (lbl_803DD978 == 0)
        {
            n = fn_801343CC(lbl_8031CC50, lbl_803A9DD0, (u8*)lbl_8031CC38, 6, lbl_803A9F38);
            (**(void (**)(u8*, int, int, int, int, int, int, int, int, int, int, int))
                    ((char*)(*gTitleMenuLinkInterface) + 4))
                (lbl_803A9DD0, n, 0, 0, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
            lbl_803DD978 = 1;
        }
        sel = (**(int (**)(void))((char*)(*gTitleMenuLinkInterface) + 0xc))();
        idx = (**(int (**)(void))((char*)(*gTitleMenuLinkInterface) + 0x14))();
        if (sel > 0)
        {
            (*gMapEventInterface)->setMapAct(0x42, lbl_8031CC38[lbl_803A9F38[idx]].b2);
        }
        (**(void (**)(int))((char*)(*gTitleMenuLinkInterface) + 0x10))(param_1);
        break;
    }
    if (lbl_803DD978 != 0 && warpstoneUIState != 4)
    {
        (**(void (**)(void))((char*)(*gTitleMenuLinkInterface) + 8))();
        lbl_803DD978 = 0;
    }
}

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

#pragma peephole off
#pragma peephole reset

#pragma peephole off
#pragma peephole reset
