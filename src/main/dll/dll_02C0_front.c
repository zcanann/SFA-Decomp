/*
 * front (DLL 0x2C0) - the title/attract-mode front-end object and its
 * UI. gTitleScreenObjDescriptor drives the title-screen actor: init
 * seeds anim moves per seqId (0x77d..0x781 = the four Tricky title
 * poses, 0x78a/0x781 the attract camera/movie), update runs the actor
 * anim state machine plus the per-actor footstep/voice sfx grid at
 * gTitleScreenSfxFlagGrid and the random blink blend, release/initialise manage the
 * 19-slot texture table at gTitleScreenTextures.
 *
 * Standalone leaf entry points cover the credits roll (creditsStart /
 * creditsStart_, walking gCreditEntries with fade-in/out), the
 * copyright/title text layout (gameTextBoxFn_80134d40,
 * titleScreenShowCopyright, titleScreenPositionElements), and the GX
 * quad emitters for the title and name-entry text (titleScreenTextDrawFunc
 * / nameEntryTextDrawFunc, writing through GXWGFifo). showCredits gates
 * the credits sequence; getCurUiDll selects the active front-end UI DLL.
 */
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/objseq.h"
#include "main/dll/FRONT/dll_0034_n_filemenu.h"
#include "main/dll/dll_003D_titlemenuitem.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

#define TITLE_SCREEN_TEXTURE_COUNT 19

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
    u8 animPhase; /* 0x30: anim state-machine phase (0-5); also the move index passed to ObjAnim_SetCurrentMove */
    s8 poseIndex; /* 0x31: per-actor pose index (seqId - 0x77d), or -2 for non-Tricky */
    u8 pad32[0x34 - 0x32];
    f32 unk34;
} TitlescreenState;

extern void* gameTextGetBox(int box);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int a);
extern void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern float mathCosf(float x);

/* ===== EN v1.0 retargeted leaves ========================================= */

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

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void) { return 56; }

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void)
{
}

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_getObjectTypeId: returns 74 if
 * obj->_46  is in [1917, 1920], else returns 0. */
int titlescreen_getObjectTypeId(u8* obj)
{
    s16 v = ((GameObject*)obj)->anim.seqId;
    if (v >= 1917 && v < 1921) return 74;
    return 0;
}

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

extern void* gTitleScreenMainTex;
void* gTitleScreenTextures[TITLE_SCREEN_TEXTURE_COUNT];
extern u8 gTitleScreenSetupDone;

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at gTitleScreenMainTex and walk the 19-slot table at gTitleScreenTextures
 * releasing each non-null entry, then clear the busy byte at
 * gTitleScreenSetupDone. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void)
{
    int i;
    textureFree(gTitleScreenMainTex);
    gTitleScreenMainTex = NULL;
    i = 0;
    do
    {
        if (gTitleScreenTextures[i] != NULL)
        {
            textureFree(gTitleScreenTextures[i]);
            gTitleScreenTextures[i] = NULL;
        }
        i++;
    }
    while (i < TITLE_SCREEN_TEXTURE_COUNT);
    gTitleScreenSetupDone = 0;
}

extern s8 lbl_803DBC08;
extern s8 lbl_803DBC09;
extern s8 lbl_803DD990;
extern s8 lbl_803DD991;
extern u8 lbl_803DC968;
extern f32 lbl_803DD9D0;
extern f32 lbl_803DD9CC;
extern f32 lbl_803DD9C4;
extern f32 lbl_803DD9B4;
extern f32 gTitleScreenCursorX;
extern int gTitleScreenCopyrightBaseY;
extern f32 lbl_803E2318;
extern f32 lbl_803E22F8;
u8 gTitleScreenMtx[0x34];
extern s16 gTitleScreenTextureIds[];
extern void PSMTXIdentity(void*);

/* EN v1.0 0x8013695C  size: 228b  titlescreen_initialise: reset state
 * bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * lbl_803DC968), identity the matrix, then load the 19-entry texture
 * table from the id list at gTitleScreenTextureIds into gTitleScreenTextures. */
void titlescreen_initialise(void)
{
    int i;
    lbl_803DBC08 = -1;
    lbl_803DD990 = 0;
    lbl_803DBC09 = -1;
    lbl_803DD991 = 0;
    if (lbl_803DC968 != 0)
    {
        gTitleScreenMainTex = textureLoadAsset(0x647);
    }
    else
    {
        gTitleScreenMainTex = textureLoadAsset(0xC5);
    }
    lbl_803DD9D0 = lbl_803E2318;
    lbl_803DD9CC = lbl_803E2318;
    PSMTXIdentity(gTitleScreenMtx);
    for (i = 0; i < TITLE_SCREEN_TEXTURE_COUNT; i++)
    {
        gTitleScreenTextures[i] = textureLoadAsset(gTitleScreenTextureIds[i]);
    }
    lbl_803DD9C4 = lbl_803E22F8;
    gTitleScreenSetupDone = 0;
    gTitleScreenCopyrightBaseY = 0;
    lbl_803DD9B4 = lbl_803E2318;
    gTitleScreenCursorX = lbl_803E2318;
    lbl_803DD9AB = 1;
}

extern u8 gTitleScreenCreditsStarted;
extern int gTitleScreenCreditsEndTriggered;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

/* EN v1.0 0x80135C2C  size: 152b  titlescreen_render: when visible and
 * ready, render via objRenderFn; once the credits flag fires, set the
 * one-shot trigger 0x57 and release the attract-mode movie buffers. */
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v == 0) return;
    if (lbl_803DD9AB == 0) return;
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E2318);
    if (showCredits == 0) return;
    if (gTitleScreenCreditsStarted != 0) return;
    GameBit_Set(0xDF6, 1);
    gTitleScreenCreditsStarted = 1;
    (*gObjectTriggerInterface)->setCamVars(0x57, 0, 0, 0);
    n_attractmode_releaseMovieBuffers();
    gTitleScreenCreditsEndTriggered = 0;
}

typedef struct TitleAnimMoves
{
    f32 moves[8];
} TitleAnimMoves;

extern TitleAnimMoves gTitleScreenAnimMoves[];
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx);

/* EN v1.0 0x801367A8  size: 252b  titlescreen_init: seed the object's
 * state from its descriptor id (obj->_46), pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
void titlescreen_init(u8* obj, u8* p)
{
    u8* a = ((GameObject*)obj)->extra;
    s16 v;
    ((TitlescreenState*)a)->animPhase = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)p[0x18] << 8);
    v = ((GameObject*)obj)->anim.seqId;
    if (v >= 0x77d && v < 0x781)
    {
        ((TitlescreenState*)a)->poseIndex = (s8)(v - 0x77d);
        ((TitlescreenState*)a)->unk34 = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E22F8, 0);
    }
    else
    {
        f32 m = lbl_803E22F8;
        ((TitlescreenState*)a)->unk34 = m;
        ((TitlescreenState*)a)->poseIndex = -2;
        v = ((GameObject*)obj)->anim.seqId;
        if (v == 0x78a)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, m, 0);
        }
        else if (v == 0x781)
        {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2318, 0);
            ObjModel_SetRenderCallback((int*)((GameObject*)obj)->anim.banks[0],
                                       AttractMovie_DrawTextureCallback);
        }
    }
}

extern f32 lbl_803E2344;
extern f32 lbl_803E2348;
extern f32 lbl_803E234C;
extern f32 lbl_803E2350;
extern f32 gTitleScreenCursorY;
extern void PSMTXTrans(void*, f32, f32, f32);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void* Obj_GetActiveModel(u8* obj);

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at gTitleScreenMtx and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma peephole on
void titleScreenPositionElements(f32 a, f32 b)
{
    PSMTXTrans(gTitleScreenMtx, a, b, lbl_803E22F8);
    gTitleScreenCursorY = (lbl_803E2344 - b) / lbl_803E2348;
    lbl_803DD9B4 = (a - lbl_803E234C) / lbl_803E2350;
    gTitleScreenCursorX = lbl_803E2318 - gTitleScreenCursorY;
}

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
void titleScreenFn_801368a4(s8 arg)
{
    s8 cur;
    if (arg == (cur = lbl_803DD991)) return;
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

extern u16 lbl_803DD994;
extern u16 gTitleScreenCreditTimer;
extern u16 gTitleScreenCreditIndex;
extern s16 gTitleScreenCreditDelay;
extern int getCurUiDll(void);
extern f32 timeDelta;

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch showCredits = 1 and zero five halfword/byte counters. */
void creditsStart(void)
{
    showCredits = 1;
    lbl_803DD994 = 0;
    gTitleScreenCreditTimer = 0;
    gTitleScreenCreditDelay = 0;
    gTitleScreenCreditIndex = 0;
    gTitleScreenCreditsStarted = 0;
}

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */
int gameTextFn_80134be8(void)
{
    int x = getCurUiDll();
    if ((u32)(x - 2) <= 4 || x == 7)
    {
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(MUSICTRIG_lose_ice_race, 0) and clear showCredits. */
extern void Music_Trigger(int id, int arg);

void titlescreen_free(u8* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x77d)
    {
        Music_Trigger(MUSICTRIG_lose_ice_race, 0);
        showCredits = 0;
    }
}

extern f32 gTitleScreenCopyrightFade;
extern u8 gTitleScreenCopyrightLatch;
extern f32 lbl_803E231C;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;
extern void* gameTextGet(int textId);

/* EN v1.0 0x80134C28  size: 280b  titleScreenShowCopyright: drive the
 * copyright/title text fade and push text box 0x3d9. */
#pragma scheduling off
#pragma peephole off
void titleScreenShowCopyright(u8 arg)
{
    void* tb;
    void* box;

    if (arg != 0)
    {
        gTitleScreenCopyrightFade = lbl_803E2318;
        gTitleScreenCopyrightLatch = 0;
    }
    else if (gTitleScreenCopyrightLatch != 0)
    {
        gTitleScreenCopyrightFade = lbl_803DD9B4;
    }
    else
    {
        gTitleScreenCopyrightFade = lbl_803E2318;
        if (lbl_803DD9B4 > lbl_803E231C)
        {
            gTitleScreenCopyrightLatch = 1;
        }
    }
    tb = gameTextGet(0x3d9);
    if (*(u16*)tb != 0xffff)
    {
        box = gameTextGetBox(*(u8*)((char*)tb + 4));
        if (gTitleScreenCopyrightBaseY == 0)
        {
            gTitleScreenCopyrightBaseY = *(s16*)((char*)box + 0x16);
        }
        *(s16*)((char*)box + 0x16) =
            (s16)(lbl_803E2320 * (lbl_803E2318 - gTitleScreenCopyrightFade) + gTitleScreenCopyrightBaseY);
        gameTextSetColor(0xff, 0xff, 0xff, (s32)(lbl_803E2324 * gTitleScreenCursorX));
        gameTextShow(0x3d9);
    }
}

extern void GXLoadPosMtxImm(f32* matrix, s32 slot);
extern void GXSetCurrentMtx(u32 id);
#define GX_ORTHOGRAPHIC 1 /* GXProjectionType (GXEnum.h): GX_PERSPECTIVE=0, GX_ORTHOGRAPHIC=1 */
extern void GXSetProjection(f32* matrix, s32 mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCullMode(int mode);
extern void GXBegin(int type, int fmt, int n);
extern void Camera_RebuildProjectionMatrix(void);
extern f32 hudMatrix[];

#define GX_VA_POS 9
#define GX_VA_TEX0 13
#define GX_DIRECT 1
#define GX_CULL_NONE 0
#define GX_QUADS 0x80
#define GX_VTXFMT1 1

volatile PPCWGPipe GXWGFifo : (0xCC008000);

void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)gTitleScreenMtx, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = x0;
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = x0;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;
    Camera_RebuildProjectionMatrix();
}

void nameEntryTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)gTitleScreenMtx, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetScissor((int)((u32) * (f32*)(gTitleScreenMtx + 0xc) + 0x39),
                 (int)((u32) * (f32*)(gTitleScreenMtx + 0x1c) + 0x4e), 0x104, 0x16);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);
    GXWGFifo.s16 = (s16)(x0 - *(u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = y0;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - *(u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)(x0 - *(u32*)&lbl_803DD9BC * 4 + 0x208);
    GXWGFifo.s16 = y1;
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
u8 gTitleScreenSfxFlagGrid[0x48];
void fn_80134870(int obj, u8* arr);

/* EN v1.0 0x80135CC8  size: 2784b  titlescreen_update: drive the title
 * screen actor anim state machine, the per-actor footstep/voice sfx flag
 * grid at gTitleScreenSfxFlagGrid, the random blink blend, and the one-shot envfx/sky
 * setup. */
void titlescreen_update(u8* obj)
{
    extern int randomGetRange(int lo, int hi);
    extern void characterDoEyeAnims(u8* obj, void* state);
    extern void fn_8003B228(u8* obj, void* p);
    extern void Sfx_StopFromObject(u8* obj, u32 sfxId);
    extern void Sfx_PlayFromObject(u8* obj, u32 sfxId);
    extern void fn_80134870(u8 * obj, u8 * arr);
    extern int ObjModel_HasActiveBlendChannels(ObjModel* model);
    extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
    extern int getEnvfxAct(int a, int b, u16 idx, int d);
    extern void skyFn_80089710(int flags, int enabled, int startComplete);
    extern void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);
    extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);


    u8* state = ((GameObject*)obj)->extra;
    int objHandle = (int)obj;
    u8* p;
    u8 c;
    int evt;
    f32 f;
    ObjModel* model;
    ObjModelBlendChannel* blend;
    int n;
    int s;
    u8* row;
    s16 t;
    u8 buf[0x1c];

    if (lbl_803DD9AB != 0)
    {
        if (((TitlescreenState*)state)->poseIndex != lbl_803DD990 && lbl_803DD991 == 0 &&
            (c = ((TitlescreenState*)state)->animPhase) != 0 && c != 4 && c != 3)
        {
            if (((GameObject*)obj)->anim.seqId == 0x77d || ((GameObject*)obj)->anim.seqId == 0x780)
            {
                ((TitlescreenState*)state)->animPhase = 3;
                ObjAnim_SetCurrentMove(objHandle, 1, lbl_803E2318, 0);
                ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[3];
            }
            else
            {
                ((TitlescreenState*)state)->animPhase = 0;
                ObjAnim_SetCurrentMove(objHandle, 0, lbl_803E22F8, 0);
                ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
            }
        }
        if (((TitlescreenState*)state)->poseIndex == lbl_803DD990 && lbl_803DD991 != 0 &&
            (c = ((TitlescreenState*)state)->animPhase) != 1 && c != 2 && c != 5)
        {
            ((TitlescreenState*)state)->animPhase = 1;
            ObjAnim_SetCurrentMove(objHandle, 1, lbl_803E22F8, 0);
            ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[1];
            if (((GameObject*)obj)->anim.seqId == 0x77e)
            {
                Sfx_StopFromObject(obj, SFXTRIG_fend_pep_snoreout);
                Sfx_StopFromObject(obj, SFXTRIG_fend_pep_snorein);
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_wakeup);
            }
        }
        t = ((GameObject*)obj)->anim.seqId;
        if (t == 0x7a7)
        {
            ((GameObject*)obj)->anim.rotX =
                lbl_803E2354 * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        }
        else if (t != 0x78a)
        {
            buf[0x1b] = 0;
            if (t == 0x77d && ((TitlescreenState*)state)->animPhase == 2)
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
            evt = ((int (*)(f32, int, f32, ObjAnimEventList*))ObjAnim_AdvanceCurrentMove)(
                f, objHandle, timeDelta, (ObjAnimEventList*)buf);
            if (evt != 0)
            {
                if (((TitlescreenState*)state)->poseIndex == lbl_803DD990 && ((TitlescreenState*)state)->animPhase == 1)
                {
                    ((TitlescreenState*)state)->animPhase = 2;
                    ObjAnim_SetCurrentMove(objHandle, 2, lbl_803E22F8, 0);
                    ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[2];
                }
                else if (((TitlescreenState*)state)->animPhase == 3)
                {
                    ((TitlescreenState*)state)->animPhase = 0;
                    ObjAnim_SetCurrentMove(objHandle, 0, lbl_803E22F8, 0);
                    ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[0];
                }
                else if (((GameObject*)obj)->anim.seqId >= 0x77d && ((GameObject*)obj)->anim.seqId < 0x781)
                {
                    if (randomGetRange(0, 4) == 0)
                    {
                        if ((c = ((TitlescreenState*)state)->animPhase) == 0 || c == 4)
                        {
                            ((TitlescreenState*)state)->animPhase = 4;
                            ObjAnim_SetCurrentMove(objHandle, randomGetRange(3, 4), lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress =
                                gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[1 + ((GameObject*)obj)->anim.
                                    currentMove];
                        }
                        else
                        {
                            ((TitlescreenState*)state)->animPhase = 5;
                            ObjAnim_SetCurrentMove(objHandle, randomGetRange(5, 6), lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress =
                                gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].moves[1 + ((GameObject*)obj)->anim.
                                    currentMove];
                        }
                    }
                    else
                    {
                        c = ((TitlescreenState*)state)->animPhase;
                        if (c == 4)
                        {
                            ((TitlescreenState*)state)->animPhase = 0;
                            ObjAnim_SetCurrentMove(objHandle, 0, lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].
                                moves[0];
                        }
                        else if (c == 5)
                        {
                            ((TitlescreenState*)state)->animPhase = 2;
                            ObjAnim_SetCurrentMove(objHandle, 2, lbl_803E22F8, 0);
                            ((TrickyState*)state)->moveProgress = gTitleScreenAnimMoves[((GameObject*)obj)->anim.seqId - 0x77d].
                                moves[2];
                        }
                    }
                }
            }
            fn_80134870(obj, buf);
        }
        t = ((GameObject*)obj)->anim.seqId;
        if (t == 0x77e && ((c = ((TitlescreenState*)state)->animPhase) == 0 || c == 4))
        {
            fn_8003B228(obj, state);
        }
        else if (t >= 0x77d && t < 0x781)
        {
            characterDoEyeAnims(obj, state);
        }
        model = Obj_GetActiveModel(obj);
        if (model->file->morphTargetCount != 0 && ObjModel_HasActiveBlendChannels(model) == 0 &&
            randomGetRange(0xf0, 0x168) == 0xf0)
        {
            blend = model->blendChannels;
            n = randomGetRange(0, model->file->morphTargetCount);
            ObjModel_SetBlendChannelTargets((int)model, 0, blend->morphTargetB, n - 1, lbl_803E2360, 0);
        }
        lbl_803DBC08 = -1;
        lbl_803DBC09 = -1;
        s = ((TitlescreenState*)state)->animPhase;
        t = ((GameObject*)obj)->anim.seqId;
        switch (t)
        {
        case 0x77d:
            break;
        case 0x77e:
            switch (s)
            {
            case 5:
                row = gTitleScreenSfxFlagGrid + (t - 0x77d) * 0x12;
                if (row[s * 3] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2364) row[s * 3] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2364)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fened_pep_yawn);
                    row[s * 3] = 1;
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
                    row = gTitleScreenSfxFlagGrid + (t - 0x77d) * 0x12;
                    if (row[s * 3] != 0)
                    {
                        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2368) row[s * 3] = 0;
                    }
                    else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2368)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
                        row[s * 3] = 1;
                    }
                    p = gTitleScreenSfxFlagGrid + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                    if (*p != 0)
                    {
                        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E236C) *p = 0;
                    }
                    else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E236C)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
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
                row = gTitleScreenSfxFlagGrid + (t - 0x77d) * 0x12;
                if (row[s * 3] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2370) row[s * 3] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2370)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_wave);
                    row[s * 3] = 1;
                }
                break;
            case 5:
                row = gTitleScreenSfxFlagGrid + (t - 0x77d) * 0x12;
                if (row[s * 3] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2374) row[s * 3] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2374)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_armout);
                    row[s * 3] = 1;
                }
                p = gTitleScreenSfxFlagGrid + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2378) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2378)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                p = gTitleScreenSfxFlagGrid + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 2;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E237C) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E237C)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_armin);
                    *p = 1;
                }
                break;
            case 2:
                row = gTitleScreenSfxFlagGrid + (t - 0x77d) * 0x12;
                if (row[s * 3] != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2368) row[s * 3] = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2368)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    row[s * 3] = 1;
                }
                p = gTitleScreenSfxFlagGrid + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 1;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2380) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2380)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                p = gTitleScreenSfxFlagGrid + (((GameObject*)obj)->anim.seqId - 0x77d) * 0x12 + s * 3 + 2;
                if (*p != 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2384) *p = 0;
                }
                else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2384)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_beep);
                    *p = 1;
                }
                break;
            }
            break;
        }
        if (gTitleScreenSetupDone == 0)
        {
            getEnvfxAct(0, 0, 0x21f, 0);
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x4b, 0x64, 0x78, 0, 0);
            skyFn_800894a8(7, lbl_803E2318, lbl_803E2388, *(f32*)&lbl_803E2388);
            (*gCameraInterface)->setFocus(obj, 0);
            gTitleScreenSetupDone = 1;
            fn_80131F0C();
        }
    }
}

void fn_80134870(int obj, u8* arr)
{
    s8* sarr = (s8*)arr;
    int i;
    for (i = 0; i < sarr[0x1b]; i++)
    {
        s8 t;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x77d:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_fox_keytap);
            }
            break;
        case 0x77e:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_snoreout);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_pep_snorein);
            }
            break;
        case 0x77f:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_kickbox);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_slip_fingersnap);
            }
            break;
        case 0x780:
            t = sarr[i + 0x13];
            if (t == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_servo2);
            }
            else if (t == 7)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fend_rob_servo1);
            }
            break;
        }
    }
}

extern u16 lbl_803DBC0A;
extern u8 lbl_803DB411;
extern void loadUiDll(int index);
extern void streamFn_8000a380(int a, int b, int c);
extern void gameTextFn_80016810(int a, int b, int c);

typedef struct
{
    u16 a;
    u16 b;
} CreditEntry;

extern CreditEntry gCreditEntries[];

void creditsStart_(void)
{
    int alpha;
    if (gTitleScreenCreditIndex >= lbl_803DBC0A)
    {
        if ((*gCameraInterface)->getMode() == 0x57)
        {
            showCredits = 0;
            loadUiDll(4);
            TitleMenu_setSelection(4);
        }
        return;
    }
    if (gTitleScreenCreditDelay > 0)
    {
        gTitleScreenCreditDelay -= lbl_803DB411;
        if (gTitleScreenCreditDelay < 0)
        {
            gTitleScreenCreditDelay = 0;
        }
        return;
    }
    if (gTitleScreenCreditTimer < 0x14)
    {
        alpha = gTitleScreenCreditTimer * 0xff / 0x14 & 0xff;
    }
    else if (gTitleScreenCreditTimer >= gCreditEntries[gTitleScreenCreditIndex].b - 0x14)
    {
        if (gTitleScreenCreditIndex == lbl_803DBC0A - 1 && gTitleScreenCreditsEndTriggered == 0)
        {
            streamFn_8000a380(3, 2, 0xfa0);
            gTitleScreenCreditsEndTriggered = 1;
        }
        alpha = 0xff - (gTitleScreenCreditTimer - gCreditEntries[gTitleScreenCreditIndex].b) * 0xff / 0x14 & 0xff;
    }
    else
    {
        alpha = 0xff;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    gameTextFn_80016810(gCreditEntries[gTitleScreenCreditIndex].a, 0, 0);
    lbl_803DD994 += lbl_803DB411;
    gTitleScreenCreditTimer += lbl_803DB411;
    if (gTitleScreenCreditTimer < gCreditEntries[gTitleScreenCreditIndex].b)
    {
        return;
    }
    gTitleScreenCreditIndex++;
    gTitleScreenCreditDelay = 0x3c;
    if (gTitleScreenCreditIndex < lbl_803DBC0A)
    {
        gTitleScreenCreditTimer = 0;
    }
}

extern void drawScaledTexture(char* tex, f32 x, f32 y, int alpha, int s, int w, int h, int mode);
extern u16 fn_80130124(void);
extern u8 lbl_803DD9C0;
extern f32 lbl_803E22F0;
extern f32 lbl_803E22F4;
extern f32 lbl_803E22FC;
extern f32 lbl_803E2300;
extern f32 lbl_803E2304;
extern f64 lbl_803E2308;
extern f32 lbl_803E2328;
extern f32 lbl_803E232C;
extern f32 gTitleScreenPi;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E233C;
extern f32 lbl_803E2340;

#pragma opt_propagation off
#pragma opt_common_subs off
void gameTextBoxFn_80134d40(int alpha, int hideHighlight, u32 showArrows)
{
    int yb;
    Texture* tex;
    int xb;
    f32* mtx;
    Texture** texs;
    Texture** texs2;
    f32 m;
    f32 sc3;
    int a;
    u16 v;
    int idx;
    int i;
    int r;

    m = (lbl_803DD9C4 = lbl_803DD9C4 + timeDelta);
    if (m > *(f32*)&lbl_803E22F0)
    {
        lbl_803DD9C4 = m - lbl_803E22F0;
    }
    lbl_803DD9C0 = lbl_803E232C *
        mathCosf(gTitleScreenPi * (lbl_803E2334 * lbl_803DD9C4) / *(f32*)&lbl_803E22F0) +
        lbl_803E2328;
    if (gTitleScreenCursorY > lbl_803E22F8)
    {
        f32* m2 = (f32*)gTitleScreenMtx;
        int xb;
        int yb;
        int w;
        xb = (int)m2[3] - 0x32;
        yb = (int)m2[7];
        texs = (Texture**)gTitleScreenTextures;
        tex = texs[4];
        drawScaledTexture((char*)tex,
                          (f32)(int)(xb + 0x5a + (texs2 = (Texture**)gTitleScreenTextures)[6]->width),
                          (f32)(int)(yb - 0x10), alpha, 0x100, tex->width,
                          (u32)(lbl_803E2300 * gTitleScreenCursorY) + 0x10, 0);
        tex = texs2[6];
        drawScaledTexture((char*)tex, (f32)(int)(xb + 0x5a), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          tex->width, (u32)(lbl_803E2300 * gTitleScreenCursorY) + 0x10, 0);
        tex = texs2[6];
        w = tex->width;
        drawScaledTexture((char*)tex,
                          (f32)(int)(xb + w + texs[4]->width + 0x57),
                          (f32)(int)(yb - 0x10), 0xff, 0x100, w,
                          (u32)(lbl_803E2300 * gTitleScreenCursorY) + 0x10, 1);
        tex = (Texture*)gTitleScreenTextures[0];
        drawScaledTexture((char*)tex, (f32)(int)(xb + 0x23), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          tex->width, (u32)(lbl_803E2300 * gTitleScreenCursorY) + 0x10, 0);
    }
    mtx = (f32*)gTitleScreenMtx;
    {
        int xb = (int)mtx[3];
        int yb = (int)mtx[7];
        int a = (gTitleScreenCursorY > lbl_803E22F8) ? 0xff : lbl_803DD9C0;
        drawTexture(gTitleScreenTextures[1], (f32)(int)(xb - 0x18),
                    (f32)(int)(yb - ((Texture*)gTitleScreenTextures[1])->height + 3), 0xff, 0xff);
        texs2 = (Texture**)gTitleScreenTextures;
        drawTexture(texs2[7], (f32)(int)(xb + 0xa1), (f32)(int)(yb - 0x2e), a, 0xff);
    }
    {
        int xb = (int)mtx[3];
        int yb = (int)mtx[7];
        f32 cy = gTitleScreenCursorY;
        int a = (cy > lbl_803E22F8) ? 0xff : lbl_803DD9C0;
        drawTexture(gTitleScreenTextures[2], (f32)(int)(xb - 0x18),
                    lbl_803E22FC + (lbl_803E2300 * cy + (f32)(int)yb), 0xff, 0xff);
        drawTexture(texs2[7], (f32)(int)(xb + 0xa1),
                    lbl_803E2304 + (lbl_803E2300 * gTitleScreenCursorY + (f32)(int)yb), a, 0xff);
    }
    gameTextSetColor(0xff, 0xff, 0xff,
                     (int)((f64)lbl_803DD9C0 * (lbl_803E2308 - gTitleScreenCursorY)));
    gameTextShow(0x3da);
    drawTexture(gTitleScreenTextures[3], (f32)(int)((int)mtx[3] - 0x32),
                (f32)(int)(0xfe - ((u32)((Texture*)gTitleScreenTextures[3])->width >> 1)), 0xff, 0xff);
    if (gTitleScreenCursorY >= lbl_803E2338 && (hideHighlight & 0xff) == 0u)
    {
        int xb = (int)mtx[3] - 0x32;
        int yb = (int)mtx[7];
        i = 0;
        texs = (Texture**)gTitleScreenTextures;
        sc3 = lbl_803E2300;
        do
        {
            tex = texs[4];
            drawScaledTexture((char*)tex,
                              (f32)(int)(xb + 0x5a + texs[6]->width -
                                  (i + 1) * 4),
                              (f32)(int)(yb - 0x10 - (i + 1) * 3),
                              (int)(u32)lbl_803DD9C0 >> (i + 3) & 0xff, 0x100,
                              tex->width + (i + 1) * 8,
                              (u32)(sc3 * gTitleScreenCursorY) + ((i + 1) * 6 + 0x10), 4);
            i++;
        }
        while (i < 4);
    }
    if (gTitleScreenCursorY > lbl_803E22F8 && (v = fn_80130124()) != 0xFFFF)
    {
        yb = *(s16*)((int)gameTextGetBox(v) + 0x16);
        xb = (int)mtx[3];
        yb += (int)mtx[7];
        if ((hideHighlight & 0xff) == 0u)
        {
            drawTexture(gTitleScreenTextures[5], (f32)(int)(xb + 0x2f),
                        (f32)(int)(yb - 1), alpha, 0xff);
        }
    }
    idx = (u8)((int)((u32)lbl_803DD9C0 << 3) / 0x100);
    texs = (Texture**)gTitleScreenTextures;
    {
        Texture* t = texs[18];
        drawScaledTexture((char*)t,
                          (f32)(int)((int)(lbl_803E22F0 * gTitleScreenCursorX) - 0x50),
                          (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                          t->width, t->height, 1);
    }
    texs2 = &((Texture**)(gTitleScreenTextures + 8))[idx];
    {
        Texture* t = *texs2;
        drawScaledTexture((char*)t,
                          (f32)(int)((int)(lbl_803E22F0 * gTitleScreenCursorX) +
                              texs[18]->width - 0x4a),
                          (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                          t->width, t->height, 0);
    }
    {
        Texture* t = texs[18];
        drawScaledTexture((char*)t,
                          (f32)(int)(0x280 - ((int)(lbl_803E22F0 * gTitleScreenCursorX) - 0x50) -
                              texs[18]->width),
                          (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                          t->width, t->height, 0);
    }
    {
        Texture* t = *texs2;
        drawScaledTexture((char*)t,
                          (f32)(int)(0x27a - ((int)(lbl_803E22F0 * gTitleScreenCursorX) - 0x50) -
                              texs[18]->width - t->width),
                          (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                          t->width, t->height, 1);
    }
    m = lbl_803DD9B4;
    if (lbl_803DD9B4 > gTitleScreenCursorX)
    {
        m = gTitleScreenCursorX;
    }
    drawTexture(gTitleScreenMainTex,
                (f32)(int)((0x280 - (((int)((Texture*)gTitleScreenMainTex)->width * 0xbe) / 0x100)) / 2),
                (f32)(int)(int)(lbl_803E2340 * m + lbl_803E233C), 0xff, 0xbe);
    if ((showArrows & 0xff) != 0u)
    {
        xb = (int)mtx[3];
        yb = (int)mtx[7];
        drawTexture(gTitleScreenTextures[17], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x14),
                    0xff, 0xff);
        drawTexture(gTitleScreenTextures[16], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x4b),
                    0xff, 0xff);
    }
}
#pragma opt_propagation reset
#pragma opt_common_subs reset

#pragma scheduling on
#pragma peephole on

TitleAnimMoves gTitleScreenAnimMoves[] =
{
    { { 0.01f, 0.01f, 0.01f, -0.01f, 0.01f, 0.01f, 0.01f, 0.01f } },
    { { 0.003f, 0.01f, 0.01f, -0.01f, 0.007f, 0.007f, 0.003f, 0.003f } },
    { { 0.01f, 0.01f, 0.01f, -0.01f, 0.01f, 0.004f, 0.01f, 0.004f } },
    { { 0.01f, 0.01f, 0.0075f, -0.01f, 0.01f, 0.01f, 0.01f, 0.01f } },
};

CreditEntry gCreditEntries[] =
{
    { 0x1FD, 0x78 },
    { 0x4CB, 0xB4 },
    { 0x4CC, 0xB4 },
    { 0x4CD, 0xB4 },
    { 0x4CE, 0xB4 },
    { 0x4CF, 0xB4 },
    { 0x4D0, 0xB4 },
    { 0x4D1, 0xB4 },
    { 0x4F4, 0xB4 },
    { 0x4D2, 0x168 },
    { 0x4D3, 0x12C },
    { 0x4D4, 0xB4 },
    { 0x4D5, 0xB4 },
    { 0x4D6, 0xB4 },
    { 0x4D8, 0xB4 },
    { 0x4D9, 0xB4 },
    { 0x4D7, 0xB4 },
    { 0x4EF, 0xB4 },
    { 0x517, 0xB4 },
    { 0x518, 0xB4 },
    { 0x519, 0xB4 },
    { 0x52A, 0xB4 },
    { 0x54A, 0xB4 },
    { 0x54B, 0xB4 },
    { 0x54C, 0xB4 },
    { 0x4DA, 0xB4 },
    { 0x4DB, 0xB4 },
    { 0x4DC, 0xB4 },
    { 0x4DD, 0xB4 },
    { 0x4DE, 0xB4 },
    { 0x4DF, 0xB4 },
    { 0x4E0, 0xB4 },
    { 0x4E1, 0xB4 },
    { 0x4E2, 0xB4 },
    { 0x4E3, 0xB4 },
    { 0x4E4, 0xB4 },
    { 0x4E5, 0xB4 },
    { 0x4E6, 0xB4 },
    { 0x4E7, 0xB4 },
    { 0x4E8, 0xB4 },
    { 0x4E9, 0xB4 },
    { 0x4EA, 0xB4 },
    { 0x4EB, 0x168 },
    { 0x4F3, 0xB4 },
    { 0x4EC, 0xB4 },
    { 0x52B, 0xB4 },
    { 0x4ED, 0xB4 },
    { 0x4EE, 0xB4 },
    { 0x4F0, 0xB4 },
    { 0x4F1, 0xB4 },
    { 0x4F2, 0xB4 },
    { 0x56D, 0xB4 },
    { 0x526, 0xB4 },
};

s16 gTitleScreenTextureIds[20] = {
    0x60B, 0x60C, 0x60D, 0x60E, 0x60F, 0x610, 0x611, 0x612, 0x619, 0x61A, 0x61B, 0x61C, 0x61D, 0x620, 0x621, 0x622, 0x61E, 0x61F, 0x618, 0x000
};
