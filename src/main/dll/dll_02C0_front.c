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

typedef struct TitlescreenState
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    u8 pad6[0x18 - 0x6];
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x30 - 0x24];
    u8 unk30;
    s8 unk31;
    u8 pad32[0x34 - 0x32];
    f32 unk34;
} TitlescreenState;

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
extern void* gameTextGetBox(int boxId);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern f32 mathCosf(f32);

extern void* lbl_803DD92C;
extern void* minimapTexture;

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
extern u32 lbl_803DD9B8;
extern u32 lbl_803DD9BC;
extern u8 lbl_803DD9AB;
extern u8 showCredits;

u8 shouldShowCredits(void) { return showCredits; }

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */
void fn_80135814(u32 a, u32 b)
{
    lbl_803DD9BC = a;
    lbl_803DD9B8 = b;
}

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */
void titleScreenFn_801368d4(void) { lbl_803DD9AB = 0; }

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
f32 fn_80138F78(u8* obj);
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void) { return 56; }

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void)
{
}

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_getObjectTypeId: returns 74 if
 * obj->_46 (s16) is in [1917, 1920], else returns 0. */
int titlescreen_getObjectTypeId(u8* obj)
{
    s16 v = ((GameObject*)obj)->anim.seqId;
    if (v >= 1917 && v < 1921) return 74;
    return 0;
}

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

extern void* lbl_803DD9D4;
extern void* lbl_803A9F98[0x13];
extern u8 lbl_803DD992;
extern void* gameTextGet(s32);

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at lbl_803DD9D4 and walk the 19-slot table at lbl_803A9F98
 * releasing each non-null entry, then clear the busy byte at
 * lbl_803DD992. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void)
{
    int i;
    textureFree(lbl_803DD9D4);
    lbl_803DD9D4 = NULL;
    i = 0;
    do
    {
        if (lbl_803A9F98[i] != NULL)
        {
            textureFree(lbl_803A9F98[i]);
            lbl_803A9F98[i] = NULL;
        }
        i++;
    }
    while (i < 19);
    lbl_803DD992 = 0;
}

extern s8 lbl_803DBC08;
extern s8 lbl_803DBC09;
extern u8 lbl_803DD990;
extern u8 lbl_803DD991;
extern u8 lbl_803DC968;
extern f32 lbl_803DD9D0;
extern f32 lbl_803DD9CC;
extern f32 lbl_803DD9C4;
extern f32 lbl_803DD9B4;
extern f32 lbl_803DD9B0;
extern int lbl_803DD9AC;
extern f32 lbl_803E2318;
extern f32 lbl_803E22F8;
extern u8 lbl_803A9FE4[0x34];
extern s16 lbl_8031CDE8[];
extern void PSMTXIdentity(void*);

/* EN v1.0 0x8013695C  size: 228b  titlescreen_initialise: reset state
 * bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * lbl_803DC968), identity the matrix, then load the 19-entry texture
 * table from the id list at lbl_8031CDE8 into lbl_803A9F98. */
void titlescreen_initialise(void)
{
    int i;
    lbl_803DBC08 = -1;
    lbl_803DD990 = 0;
    lbl_803DBC09 = -1;
    lbl_803DD991 = 0;
    if (lbl_803DC968 != 0)
    {
        lbl_803DD9D4 = textureLoadAsset(0x647);
    }
    else
    {
        lbl_803DD9D4 = textureLoadAsset(0xC5);
    }
    lbl_803DD9D0 = lbl_803E2318;
    lbl_803DD9CC = lbl_803E2318;
    PSMTXIdentity(lbl_803A9FE4);
    for (i = 0; i < 19; i++)
    {
        lbl_803A9F98[i] = textureLoadAsset(lbl_8031CDE8[i]);
    }
    lbl_803DD9C4 = lbl_803E22F8;
    lbl_803DD992 = 0;
    lbl_803DD9AC = 0;
    lbl_803DD9B4 = lbl_803E2318;
    lbl_803DD9B0 = lbl_803E2318;
    lbl_803DD9AB = 1;
}

extern u8 lbl_803DD9AA;
extern int lbl_803DD9A4;
extern void objRenderFn_8003b8f4(f32);

/* EN v1.0 0x80135C2C  size: 152b  titlescreen_render: when visible and
 * ready, render via objRenderFn; once the credits flag fires, set the
 * one-shot trigger 0x57 and release the attract-mode movie buffers. */
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v == 0) return;
    if (lbl_803DD9AB == 0) return;
    objRenderFn_8003b8f4(lbl_803E2318);
    if (showCredits == 0) return;
    if (lbl_803DD9AA != 0) return;
    GameBit_Set(0xDF6, 1);
    lbl_803DD9AA = 1;
    (*gObjectTriggerInterface)->setCamVars(0x57, 0, 0, 0);
    n_attractmode_releaseMovieBuffers();
    lbl_803DD9A4 = 0;
}

typedef struct TitleAnimMoves
{
    f32 moves[8];
} TitleAnimMoves;

extern TitleAnimMoves lbl_8031CE10[];
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void AttractMovie_DrawTextureCallback(void);

/* EN v1.0 0x801367A8  size: 252b  titlescreen_init: seed the object's
 * state from its descriptor id (obj->_46), pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
void titlescreen_init(u8* obj, u8* p)
{
    u8* a = ((GameObject*)obj)->extra;
    s16 v;
    ((TitlescreenState*)a)->unk30 = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)p[0x18] << 8);
    v = ((GameObject*)obj)->anim.seqId;
    if (v >= 0x77d && v < 0x781)
    {
        ((TitlescreenState*)a)->unk31 = (s8)(v - 0x77d);
        ((TitlescreenState*)a)->unk34 = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E22F8, 0);
    }
    else
    {
        ((TitlescreenState*)a)->unk34 = lbl_803E22F8;
        ((TitlescreenState*)a)->unk31 = -2;
        v = ((GameObject*)obj)->anim.seqId;
        if (v == 0x78a)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E22F8, 0);
        }
        else if (v == 0x781)
        {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2318, 0);
            ObjModel_SetRenderCallback(*(int**)(*(int**)&((GameObject*)obj)->anim.banks),
                                       (void*)AttractMovie_DrawTextureCallback);
        }
    }
}

extern f32 lbl_803E23E8;

extern f32 lbl_803E2344;
extern f32 lbl_803E2348;
extern f32 lbl_803E234C;
extern f32 lbl_803E2350;
extern f32 lbl_803DD9C8;
extern void PSMTXTrans(void*, f32, f32, f32);

extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void* obj);
extern int sprintf(char* buf, const char* fmt, ...);
extern f32 lbl_803E22A0;
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

extern void viewFn_80129cbc(f32 a, f32 b, f32 c);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int* Obj_GetActiveModel(void* obj);

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at lbl_803A9FE4 and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma peephole on
void titleScreenPositionElements(f32 a, f32 b)
{
    PSMTXTrans(lbl_803A9FE4, a, b, lbl_803E22F8);
    lbl_803DD9C8 = (lbl_803E2344 - b) / lbl_803E2348;
    lbl_803DD9B4 = (a - lbl_803E234C) / lbl_803E2350;
    lbl_803DD9B0 = lbl_803E2318 - lbl_803DD9C8;
}

extern void* lbl_803DD960;
extern f32 lbl_803E2408;

/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
#pragma scheduling off
void titleScreenFn_801368a4(s8 arg)
{
    u8 cur;
    if (arg == (s8)(cur = lbl_803DD991)) return;
    lbl_803DBC09 = cur;
    lbl_803DD991 = arg;
}

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */
void titleScreenFn_801368c4(u8 arg)
{
    lbl_803DBC08 = lbl_803DD990;
    lbl_803DD990 = arg;
}

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void trickyImpress(u8* obj);

extern u16 lbl_803DD994;
extern u16 lbl_803DD996;
extern u16 lbl_803DD998;
extern s16 lbl_803DD9A8;
extern int getCurUiDll(void);

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
extern f32 timeDelta;

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch showCredits = 1 and zero five halfword/byte counters. */
#pragma scheduling off
void creditsStart(void)
{
    showCredits = 1;
    lbl_803DD994 = 0;
    lbl_803DD996 = 0;
    lbl_803DD9A8 = 0;
    lbl_803DD998 = 0;
    lbl_803DD9AA = 0;
}

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */
#pragma scheduling on
int gameTextFn_80134be8(void)
{
    int x = getCurUiDll();
    if ((u32)(x - 2) <= 4 || x == 7)
    {
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */
void fn_80133934(void);

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(0x3a, 0) and clear showCredits. */
extern void Music_Trigger(s32 triggerId, s32 mode);

void titlescreen_free(u8* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x77d)
    {
        Music_Trigger(0x3a, 0);
        showCredits = 0;
    }
}

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &lbl_803AB118. */
extern u8 lbl_803AB118[];

extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);

extern f32 lbl_803DD99C;
extern u8 lbl_803DD9A0;
extern f32 lbl_803E231C;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;

#pragma scheduling off
#pragma peephole off
void titleScreenShowCopyright(u8 arg)
{
    void* tb;
    void* box;

    if (arg != 0)
    {
        lbl_803DD99C = lbl_803E2318;
        lbl_803DD9A0 = 0;
    }
    else if (lbl_803DD9A0 != 0)
    {
        lbl_803DD99C = lbl_803DD9B4;
    }
    else
    {
        lbl_803DD99C = lbl_803E2318;
        if (lbl_803DD9B4 > lbl_803E231C)
        {
            lbl_803DD9A0 = 1;
        }
    }
    tb = gameTextGet(0x3d9);
    if (*(u16*)tb != 0xffff)
    {
        box = gameTextGetBox(*(u8*)((char*)tb + 4));
        if (lbl_803DD9AC == 0)
        {
            lbl_803DD9AC = *(s16*)((char*)box + 0x16);
        }
        *(s16*)((char*)box + 0x16) =
            (s16)(lbl_803E2320 * (lbl_803E2318 - lbl_803DD99C) + (f32)lbl_803DD9AC);
        gameTextSetColor(0xff, 0xff, 0xff, (s32)(lbl_803E2324 * lbl_803DD9B0));
        gameTextShow(0x3d9);
    }
}

extern void GXLoadPosMtxImm(f32* matrix, s32 slot);
extern void GXSetCurrentMtx(int id);
extern void GXSetProjection(f32* matrix, s32 mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCullMode(int mode);
extern void GXBegin(int type, int fmt, int n);
extern void Camera_RebuildProjectionMatrix(void);
extern f32 hudMatrix[];

volatile PPCWGPipe GXWGFifo : (0xCC008000);

void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)lbl_803A9FE4, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, 1);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)x0;
    GXWGFifo.s16 = (s16)y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)x1;
    GXWGFifo.s16 = (s16)y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)x1;
    GXWGFifo.s16 = (s16)y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)x0;
    GXWGFifo.s16 = (s16)y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
    Camera_RebuildProjectionMatrix();
}

void nameEntryTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)lbl_803A9FE4, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, 1);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    GXSetScissor((int)((u32) * (f32*)(lbl_803A9FE4 + 0xc) + 0x39),
                 (int)((u32) * (f32*)(lbl_803A9FE4 + 0x1c) + 0x4e), 0x104, 0x16);
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)(x0 - *(volatile u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = (s16)y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(volatile u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = (s16)y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(volatile u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = (s16)y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)(x0 - *(volatile u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = (s16)y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
    GXSetScissor(0, 0, 0x280, 0x1e0);
    Camera_RebuildProjectionMatrix();
}

extern f32 lbl_803E2354;
extern f32 lbl_803E2358;
extern f32 lbl_803E235C;
extern f32 lbl_803E2360;
extern f32 lbl_803E2364;
extern f32 lbl_803E2368;
extern f32 lbl_803E236C;
extern f32 lbl_803E2370;
extern f32 lbl_803E2374;
extern f32 lbl_803E2378;
extern f32 lbl_803E237C;
extern f32 lbl_803E2380;
extern f32 lbl_803E2384;
extern f32 lbl_803E2388;
extern f32 lbl_803DBC0C;
extern u8 lbl_803A9F50[0x48];
extern void Sfx_StopFromObject(int obj, int id);
void fn_80134870(int obj, u8* arr);

/* EN v1.0 0x80135CC8  size: 2784b  titlescreen_update: drive the title
 * screen actor anim state machine, the per-actor footstep/voice sfx flag
 * grid at lbl_803A9F50, the random blink blend, and the one-shot envfx/sky
 * setup. */
void titlescreen_update(u8* obj)
{
    extern int randomGetRange(int min, int max);
    extern void characterDoEyeAnims(u8* obj, void* state);
    extern void fn_8003B228(u8* obj, void* p);
    extern void Sfx_StopFromObject(u8* obj, u32 sfxId);
    extern void Sfx_PlayFromObject(u8* obj, u32 sfxId);
    extern void fn_80134870(u8 * obj, u8 * arr);
    extern int ObjModel_HasActiveBlendChannels(int* model);
    extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
    extern void getEnvfxAct(int a, int b, int c, int d);
    extern void skyFn_80089710(int flags, int enabled, int startComplete);
    extern void skyFn_800895e0(int id, int red, int green, int blue, int m1, int m2);
    extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
    extern void fn_80131F0C(void);
    extern f32 timeDelta;

    u8* state = ((GameObject*)obj)->extra;
    s16 t;
    u8 c;
    int evt;
    f32 f;
    int* model;
    int tmp;
    int n;
    int s;
    u8* row;
    int col;
    u8* p;
    u8 buf[0x1c];

    if (lbl_803DD9AB != 0)
    {
        if ((s8)state[0x31] != (s8)lbl_803DD990 && (s8)lbl_803DD991 == 0 &&
            (c = state[0x30]) != 0 && c != 4 && c != 3)
        {
            if (((GameObject*)obj)->anim.seqId == 0x77d || ((GameObject*)obj)->anim.seqId == 0x780)
            {
                state[0x30] = 3;
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E2318, 0);
                ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[3];
            }
            else
            {
                state[0x30] = 0;
                ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E22F8, 0);
                ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
            }
        }
        if ((s8)state[0x31] == (s8)lbl_803DD990 && (s8)lbl_803DD991 != 0 &&
            (c = state[0x30]) != 1 && c != 2 && c != 5)
        {
            state[0x30] = 1;
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E22F8, 0);
            ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[1];
            if (((GameObject*)obj)->anim.seqId == 0x77e)
            {
                Sfx_StopFromObject(obj, 0x370);
                Sfx_StopFromObject(obj, 0x36c);
                Sfx_PlayFromObject(obj, 0x36d);
            }
        }
        t = ((GameObject*)obj)->anim.seqId;
        if (t == 0x7a7)
        {
            *(s16*)obj = lbl_803E2354 * timeDelta + (f32) * (s16*)obj;
        }
        else if (t != 0x78a)
        {
            buf[0x1b] = 0;
            if (t == 0x77d && state[0x30] == 2)
            {
                if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2358)
                {
                    lbl_803DBC0C = f = lbl_803E235C * (f32)(int)
                    randomGetRange(0x32, 0x96);
                }
                else
                {
                    f = lbl_803DBC0C;
                }
            }
            else
            {
                f = ((TrickyState*)state)->moveProgress;
            }
            evt = ObjAnim_AdvanceCurrentMove(f, timeDelta, (int)obj, (ObjAnimEventList*)buf);
            if (evt != 0)
            {
                if ((s8)state[0x31] == (s8)lbl_803DD990 && state[0x30] == 1)
                {
                    state[0x30] = 2;
                    ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E22F8, 0);
                    ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[2];
                }
                else if (state[0x30] == 3)
                {
                    state[0x30] = 0;
                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E22F8, 0);
                    ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
                }
                else if (((GameObject*)obj)->anim.seqId >= 0x77d && ((GameObject*)obj)->anim.seqId < 0x781)
                {
                    if (randomGetRange(0, 4) == 0)
                    {
                        if ((c = state[0x30]) == 0 || c == 4)
                        {
                            state[0x30] = 4;
                            ObjAnim_SetCurrentMove((int)obj, randomGetRange(3, 4), lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress =
                                lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[1 + ((GameObject*)obj)->anim.
                                    currentMove];
                        }
                        else
                        {
                            state[0x30] = 5;
                            ObjAnim_SetCurrentMove((int)obj, randomGetRange(5, 6), lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress =
                                lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].moves[1 + ((GameObject*)obj)->anim.
                                    currentMove];
                        }
                    }
                    else
                    {
                        c = state[0x30];
                        if (c == 4)
                        {
                            state[0x30] = 0;
                            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].
                                moves[0];
                        }
                        else if (c == 5)
                        {
                            state[0x30] = 2;
                            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress = lbl_8031CE10[((GameObject*)obj)->anim.seqId - 0x77d].
                                moves[2];
                        }
                    }
                }
            }
            fn_80134870(obj, buf);
        }
        t = ((GameObject*)obj)->anim.seqId;
        if (t == 0x77e && ((c = state[0x30]) == 0 || c == 4))
        {
            fn_8003B228(obj, state);
        }
        else if (t >= 0x77d && t < 0x781)
        {
            characterDoEyeAnims(obj, state);
        }
        model = Obj_GetActiveModel(obj);
        if (*(u8*)(*model + 0xf9) != 0 && ObjModel_HasActiveBlendChannels(model) == 0 &&
            randomGetRange(0xf0, 0x168) == 0xf0)
        {
            tmp = *(int*)&((ObjDef*)model)->weaponDaTable;
            n = randomGetRange(0, *(u8*)(*model + 0xf9));
            ObjModel_SetBlendChannelTargets((int)model, 0, *(s8*)(tmp + 0xd), n - 1, lbl_803E2360, 0);
        }
        lbl_803DBC08 = -1;
        lbl_803DBC09 = -1;
        s = state[0x30];
        t = ((GameObject*)obj)->anim.seqId;
        switch (t)
        {
        case 0x77d:
            break;
        case 0x77e:
            switch (s)
            {
            case 5:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2364) row[col] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2364)
                {
                    Sfx_PlayFromObject(obj, 0x41d);
                    row[col] = 1;
                }
                break;
            }
            break;
        case 0x77f:
            switch (s)
            {
            case 4:
            case 5:
                if (((GameObject*)obj)->anim.currentMove == 3 || ((GameObject*)obj)->anim.currentMove == 5)
                {
                    row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                    col = s * 3;
                    if (row[col] != 0)
                    {
                        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2368) row[col] = 0;
                    }
                    else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2368)
                    {
                        Sfx_PlayFromObject(obj, 0x421);
                        row[col] = 1;
                    }
                    p = lbl_803A9F50 + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                    if (*p != 0)
                    {
                        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E236C) *p = 0;
                    }
                    else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E236C)
                    {
                        Sfx_PlayFromObject(obj, 0x421);
                        *p = 1;
                    }
                }
                break;
            }
            break;
        case 0x780:
            switch (s)
            {
            case 4:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2370) row[col] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2370)
                {
                    Sfx_PlayFromObject(obj, 0x414);
                    row[col] = 1;
                }
                break;
            case 5:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2374) row[col] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2374)
                {
                    Sfx_PlayFromObject(obj, 0x412);
                    row[col] = 1;
                }
                p = lbl_803A9F50 + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2378) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2378)
                {
                    Sfx_PlayFromObject(obj, 0x426);
                    *p = 1;
                }
                p = lbl_803A9F50 + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 2;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E237C) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E237C)
                {
                    Sfx_PlayFromObject(obj, 0x413);
                    *p = 1;
                }
                break;
            case 2:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2368) row[col] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2368)
                {
                    Sfx_PlayFromObject(obj, 0x426);
                    row[col] = 1;
                }
                p = lbl_803A9F50 + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2380) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2380)
                {
                    Sfx_PlayFromObject(obj, 0x426);
                    *p = 1;
                }
                p = lbl_803A9F50 + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 2;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2384) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2384)
                {
                    Sfx_PlayFromObject(obj, 0x426);
                    *p = 1;
                }
                break;
            }
            break;
        }
        if (lbl_803DD992 == 0)
        {
            getEnvfxAct(0, 0, 0x21f, 0);
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x4b, 0x64, 0x78, 0, 0);
            skyFn_800894a8(7, lbl_803E2318, lbl_803E2388, *(f32*)&lbl_803E2388);
            (*gCameraInterface)->setFocus(obj, 0);
            lbl_803DD992 = 1;
            fn_80131F0C();
        }
    }
}

void fn_80134870(int obj, u8* arr)
{
    int i;
    for (i = 0; i < (s8)arr[0x1b]; i++)
    {
        s8 t;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x77d:
            t = (s8)arr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, 0x368);
            }
            break;
        case 0x77e:
            t = (s8)arr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, 0x370);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, 0x36c);
            }
            break;
        case 0x77f:
            t = (s8)arr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, 0x36b);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, 0x421);
            }
            break;
        case 0x780:
            t = (s8)arr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, 0x36a);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, 0x369);
            }
            break;
        }
    }
}

extern u16 lbl_803DBC0A;
extern u8 lbl_803DB411;
extern int loadUiDll(int dllId);
extern void TitleMenu_setSelection(int sel);
extern void streamFn_8000a380(int a, int b, int c);
extern void gameTextFn_80016810(int textId, int a, int b);

typedef struct
{
    u16 a;
    u16 b;
} CreditEntry;

extern CreditEntry gCreditEntries[];

void creditsStart_(void)
{
    u8 alpha;
    if (lbl_803DD998 >= lbl_803DBC0A)
    {
        if ((*gCameraInterface)->getMode() == 0x57)
        {
            showCredits = 0;
            loadUiDll(4);
            TitleMenu_setSelection(4);
        }
        return;
    }
    if (lbl_803DD9A8 > 0)
    {
        lbl_803DD9A8 = lbl_803DD9A8 - lbl_803DB411;
        if (lbl_803DD9A8 < 0)
        {
            lbl_803DD9A8 = 0;
        }
        return;
    }
    if (lbl_803DD996 < 0x14)
    {
        alpha = (u8)(lbl_803DD996 * 0xff / 0x14);
    }
    else if (lbl_803DD996 >= gCreditEntries[lbl_803DD998].b - 0x14)
    {
        if (lbl_803DD998 == lbl_803DBC0A - 1 && lbl_803DD9A4 == 0)
        {
            streamFn_8000a380(3, 2, 0xfa0);
            lbl_803DD9A4 = 1;
        }
        alpha = (u8)(0xff - (lbl_803DD996 - gCreditEntries[lbl_803DD998].b) * 0xff / 0x14);
    }
    else
    {
        alpha = 0xff;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    gameTextFn_80016810(gCreditEntries[lbl_803DD998].a, 0, 0);
    lbl_803DD994 += lbl_803DB411;
    lbl_803DD996 += lbl_803DB411;
    if (lbl_803DD996 < gCreditEntries[lbl_803DD998].b)
    {
        return;
    }
    lbl_803DD998++;
    lbl_803DD9A8 = 0x3c;
    if (lbl_803DD998 < lbl_803DBC0A)
    {
        lbl_803DD996 = 0;
    }
}

extern void CMenu_SetFadeCounter(int v);

extern int ObjGroup_FindNearestObject(int type, int obj, f32* distOut);

extern void drawScaledTexture(char* tex, f32 x, f32 y, int alpha, int s, int w, int h, int mode);
extern s16 fn_80130124(void);
extern u8 lbl_803DD9C0;
extern f32 lbl_803E22F0;
extern f32 lbl_803E22F4;
extern f32 lbl_803E22FC;
extern f32 lbl_803E2300;
extern f32 lbl_803E2304;
extern f64 lbl_803E2308;
extern f64 lbl_803E2310;
extern f32 lbl_803E2328;
extern f32 lbl_803E232C;
extern f32 lbl_803E2330;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E233C;
extern f32 lbl_803E2340;

void gameTextBoxFn_80134d40(int p1, int p2, u32 p3)
{
    int xb;
    int yb;
    int i;
    int r;
    u8 a;
    s16 v;
    Texture* tex;
    int box;
    u8 idx;
    f32 m;
    f32 sc3;

    lbl_803DD9C4 = lbl_803DD9C4 + timeDelta;
    if (lbl_803DD9C4 > lbl_803E22F0)
    {
        lbl_803DD9C4 = lbl_803DD9C4 - lbl_803E22F0;
    }
    lbl_803DD9C0 = lbl_803E232C *
        mathCosf(lbl_803E2330 * (lbl_803E2334 * lbl_803DD9C4) / lbl_803E22F0) +
        lbl_803E2328;
    if (lbl_803DD9C8 > lbl_803E22F8)
    {
        xb = (int)*(f32*)(lbl_803A9FE4 + 0xc);
        yb = (int)*(f32*)(lbl_803A9FE4 + 0x1c);
        tex = (Texture*)lbl_803A9F98[4];
        drawScaledTexture((char*)tex,
                          (f32)(int)(xb - 0x32 + ((Texture*)lbl_803A9F98[6])->width + 0x5a),
                          (f32)(int)(yb - 0x10), p1, 0x100, tex->width,
                          (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
        tex = (Texture*)lbl_803A9F98[6];
        drawScaledTexture((char*)tex, (f32)(int)(xb + 0x28), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          tex->width, (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
        tex = (Texture*)lbl_803A9F98[6];
        drawScaledTexture((char*)tex,
                          (f32)(int)(xb - 0x32 + ((Texture*)lbl_803A9F98[4])->width +
                              tex->width + 0x57),
                          (f32)(int)(yb - 0x10), 0xff, 0x100, tex->width,
                          (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 1);
        tex = (Texture*)lbl_803A9F98[0];
        drawScaledTexture((char*)tex, (f32)(int)(xb - 0xf), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          tex->width, (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
    }
    xb = (int)*(f32*)(lbl_803A9FE4 + 0xc);
    yb = (int)*(f32*)(lbl_803A9FE4 + 0x1c);
    a = lbl_803DD9C0;
    if (lbl_803DD9C8 > lbl_803E22F8)
    {
        a = 0xff;
    }
    drawTexture(lbl_803A9F98[1], (f32)(int)(xb - 0x18),
                (f32)(int)(yb - ((Texture*)lbl_803A9F98[1])->height + 3), 0xff, 0xff);
    drawTexture(lbl_803A9F98[7], (f32)(int)(xb + 0xa1), (f32)(int)(yb - 0x2e), a, 0xff);
    xb = (int)*(f32*)(lbl_803A9FE4 + 0xc);
    yb = (int)*(f32*)(lbl_803A9FE4 + 0x1c);
    a = lbl_803DD9C0;
    if (lbl_803DD9C8 > lbl_803E22F8)
    {
        a = 0xff;
    }
    drawTexture(lbl_803A9F98[2], (f32)(int)(xb - 0x18),
                lbl_803E22FC + lbl_803E2300 * lbl_803DD9C8 + (f32)(int)yb, 0xff, 0xff);
    drawTexture(lbl_803A9F98[7], (f32)(int)(xb + 0xa1),
                lbl_803E2304 + lbl_803E2300 * lbl_803DD9C8 + (f32)(int)yb, a, 0xff);
    gameTextSetColor(0xff, 0xff, 0xff,
                     (int)(((f64)lbl_803DD9C0 - lbl_803E2310) * (lbl_803E2308 - (f64)lbl_803DD9C8)));
    gameTextShow(0x3da);
    drawTexture(lbl_803A9F98[3], (f32)(int)((int)*(f32*)(lbl_803A9FE4 + 0xc) - 0x32),
                (f32)(int)(0xfe - (((Texture*)lbl_803A9F98[3])->width >> 1)), 0xff, 0xff);
    if (lbl_803DD9C8 >= lbl_803E2338 && (p2 & 0xff) == 0)
    {
        xb = (int)*(f32*)(lbl_803A9FE4 + 0xc);
        yb = (int)*(f32*)(lbl_803A9FE4 + 0x1c);
        i = 0;
        sc3 = lbl_803E2300;
        do
        {
            tex = (Texture*)lbl_803A9F98[4];
            r = (u32)(sc3 * lbl_803DD9C8);
            drawScaledTexture((char*)tex,
                              (f32)(int)(xb + ((Texture*)lbl_803A9F98[6])->width + 0x28 +
                                  (i + 1) * -4),
                              (f32)(int)(yb - 0x10 + (i + 1) * -3),
                              (int)(u32)lbl_803DD9C0 >> ((i + 3) & 0x3f) & 0xff, 0x100,
                              tex->width + (i + 1) * 8, r + (i + 1) * 6 + 0x10, 4);
            i++;
        }
        while (i < 4);
    }
    if (lbl_803DD9C8 > lbl_803E22F8 && (v = fn_80130124()) != -1)
    {
        box = (int)gameTextGetBox(v);
        if ((p2 & 0xff) == 0)
        {
            drawTexture(lbl_803A9F98[5],
                        (f32)(int)((int)*(f32*)(lbl_803A9FE4 + 0xc) + 0x2f),
                        (f32)(int)(*(s16*)(box + 0x16) + (int)*(f32*)(lbl_803A9FE4 + 0x1c) - 1), p2, 0xff);
        }
    }
    drawScaledTexture((char*)lbl_803A9F98[18],
                      (f32)(int)((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      ((Texture*)lbl_803A9F98[18])->width,
                      ((Texture*)lbl_803A9F98[18])->height, 1);
    idx = (int)((u32)lbl_803DD9C0 << 3) / 0x100;
    tex = (Texture*)lbl_803A9F98[8 + idx];
    drawScaledTexture((char*)tex,
                      (f32)(int)((int)(lbl_803E22F0 * lbl_803DD9B0) +
                          ((Texture*)lbl_803A9F98[18])->width - 0x4a),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      tex->width, tex->height, 0);
    drawScaledTexture((char*)lbl_803A9F98[18],
                      (f32)(int)(0x280 - ((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50) -
                          ((Texture*)lbl_803A9F98[18])->width),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      ((Texture*)lbl_803A9F98[18])->width,
                      ((Texture*)lbl_803A9F98[18])->height, 0);
    tex = (Texture*)lbl_803A9F98[8 + idx];
    drawScaledTexture((char*)tex,
                      (f32)(int)(0x27a - ((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50) -
                          ((Texture*)lbl_803A9F98[18])->width - tex->width),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      tex->width, tex->height, 1);
    m = lbl_803DD9B4;
    if (lbl_803DD9B4 > lbl_803DD9B0)
    {
        m = lbl_803DD9B0;
    }
    drawTexture(lbl_803DD9D4,
                (f32)(int)((0x280 - ((int)((u32)((Texture*)lbl_803DD9D4)->width * 0xbe) >> 8)) / 2),
                (f32)(int)(int)(lbl_803E2340 * m + lbl_803E233C), 0xff, 0xbe);
    if ((p3 & 0xff) != 0)
    {
        xb = (int)*(f32*)(lbl_803A9FE4 + 0xc);
        yb = (int)*(f32*)(lbl_803A9FE4 + 0x1c);
        drawTexture(lbl_803A9F98[17], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x14),
                    0xff, 0xff);
        drawTexture(lbl_803A9F98[16], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x4b),
                    0xff, 0xff);
    }
}

extern u16* debugFrameBuffer;
